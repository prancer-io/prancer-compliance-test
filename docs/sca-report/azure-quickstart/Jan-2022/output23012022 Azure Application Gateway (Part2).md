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

## Azure Application Gateway (Part2) Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description               |
|:----------|:--------------------------|
| timestamp | 1642953583190             |
| snapshot  | master-snapshot_gen       |
| container | scenario-azure-quickStart |
| test      | master-test.json          |

## Results

### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

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
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1482                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1483                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1484                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1485                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1486                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1487                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1488                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1489                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1490                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1491                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **failed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1492                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1493                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **failed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1495                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/applicationgateways', 'microsoft.authorization/locks']                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf-firewall-policy/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf-firewall-policy/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1496                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.dbformysql/servers', 'microsoft.network/publicipaddresses', 'microsoft.web/sites', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1498                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **failed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

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
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service/diagnostics', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.apimanagement/service', 'microsoft.web/sites', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.insights/diagnosticsettings', 'microsoft.apimanagement/service/loggers', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.network/privatednszones/a', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows setting public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-ARM-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1798                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.web/sites', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-004
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

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
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.insights/autoscalesettings', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT586                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerinstance/containergroups', 'microsoft.network/networkprofiles', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

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
| resourceTypes | ['microsoft.containerservice/managedclusters', 'microsoft.network/publicipprefixes', 'microsoft.storage/storageaccounts', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.authorization/roleassignments', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.containerregistry/registries', 'microsoft.network/natgateways', 'microsoft.network/bastionhosts', 'microsoft.operationsmanagement/solutions', 'microsoft.network/privateendpoints', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.insights/activitylogalerts', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT611                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT709                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/publicipaddresses', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/applicationgateways', 'microsoft.cdn/profiles'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT737                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.compute/availabilitysets', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT783                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT801                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT889                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT919                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.apimanagement/service', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1167                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1172                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

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
| resourceTypes | ['microsoft.containerservice/managedclusters', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.authorization/roleassignments', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.containerregistry/registries', 'microsoft.network/bastionhosts', 'microsoft.operationsmanagement/solutions', 'microsoft.network/privateendpoints', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.insights/activitylogalerts', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1479                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

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
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1482                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1483                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1484                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1485                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1486                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1487                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1488                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1489                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1490                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1491                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1492                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1493                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1495                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/applicationgateways', 'microsoft.authorization/locks']                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf-firewall-policy/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf-firewall-policy/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1496                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.dbformysql/servers', 'microsoft.network/publicipaddresses', 'microsoft.web/sites', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1498                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

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
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service/diagnostics', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.apimanagement/service', 'microsoft.web/sites', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.insights/diagnosticsettings', 'microsoft.apimanagement/service/loggers', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.network/privatednszones/a', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows setting backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-ARM-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1798                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.web/sites', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-005
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

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
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.insights/autoscalesettings', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT586                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerinstance/containergroups', 'microsoft.network/networkprofiles', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

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
| resourceTypes | ['microsoft.containerservice/managedclusters', 'microsoft.network/publicipprefixes', 'microsoft.storage/storageaccounts', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.authorization/roleassignments', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.containerregistry/registries', 'microsoft.network/natgateways', 'microsoft.network/bastionhosts', 'microsoft.operationsmanagement/solutions', 'microsoft.network/privateendpoints', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.insights/activitylogalerts', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT611                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT709                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/publicipaddresses', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/applicationgateways', 'microsoft.cdn/profiles'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT737                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.compute/availabilitysets', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT783                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT801                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT889                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT919                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.apimanagement/service', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1167                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1172                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

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
| resourceTypes | ['microsoft.containerservice/managedclusters', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.authorization/roleassignments', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.containerregistry/registries', 'microsoft.network/bastionhosts', 'microsoft.operationsmanagement/solutions', 'microsoft.network/privateendpoints', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.insights/activitylogalerts', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1479                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

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
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1482                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1483                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1484                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1485                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1486                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1487                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1488                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1489                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1490                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1491                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1492                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1493                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1495                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/applicationgateways', 'microsoft.authorization/locks']                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf-firewall-policy/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf-firewall-policy/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1496                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.dbformysql/servers', 'microsoft.network/publicipaddresses', 'microsoft.web/sites', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1498                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

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
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service/diagnostics', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.apimanagement/service', 'microsoft.web/sites', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.insights/diagnosticsettings', 'microsoft.apimanagement/service/loggers', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.network/privatednszones/a', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways that don't have SSL certificates stored in keyVault and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-ARM-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1798                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.web/sites', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-006
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


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

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
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.insights/autoscalesettings', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT586                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerinstance/containergroups', 'microsoft.network/networkprofiles', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **passed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

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
| resourceTypes | ['microsoft.containerservice/managedclusters', 'microsoft.network/publicipprefixes', 'microsoft.storage/storageaccounts', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.authorization/roleassignments', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.containerregistry/registries', 'microsoft.network/natgateways', 'microsoft.network/bastionhosts', 'microsoft.operationsmanagement/solutions', 'microsoft.network/privateendpoints', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.insights/activitylogalerts', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT611                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT709                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/publicipaddresses', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/applicationgateways', 'microsoft.cdn/profiles'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT737                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.compute/availabilitysets', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT783                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT801                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT889                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **passed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT919                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.apimanagement/service', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1167                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1172                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **passed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

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
| resourceTypes | ['microsoft.containerservice/managedclusters', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.authorization/roleassignments', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.containerregistry/registries', 'microsoft.network/bastionhosts', 'microsoft.operationsmanagement/solutions', 'microsoft.network/privateendpoints', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.insights/activitylogalerts', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1479                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

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
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1482                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1483                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1484                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1485                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1486                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1487                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1488                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1489                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1490                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1491                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1492                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1493                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1495                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/applicationgateways', 'microsoft.authorization/locks']                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf-firewall-policy/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf-firewall-policy/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1496                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.dbformysql/servers', 'microsoft.network/publicipaddresses', 'microsoft.web/sites', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1498                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks', 'microsoft.network/publicipaddresses']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **passed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

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
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service/diagnostics', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.apimanagement/service', 'microsoft.web/sites', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.insights/diagnosticsettings', 'microsoft.apimanagement/service/loggers', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.network/privatednszones/a', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.operationalinsights/workspaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at <a href='https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/' target='_blank'>here</a>\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-ARM-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1798                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.web/sites', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-AGW-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------

