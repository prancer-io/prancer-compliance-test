# Automated Vulnerability Scan result and Static Code Analysis for Azure QuickStart Templates (Dec 2021)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20AKS.md
#### Application Gateways (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20Application%20Gateways%20(Part1).md
#### Application Gateways (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20Application%20Gateways%20(Part2).md
#### KV (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part1).md
#### KV (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part2).md
#### KV (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part3).md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20PostgreSQL.md
#### SQL Servers: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20SQL%20Servers.md
#### VM (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part1).md
#### VM (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part2).md
#### VM (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part3).md
#### VM (Part4): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part4).md
#### VM (Part5): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part5).md
#### VM (Part6): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part6).md

## Azure SQL Servers Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description                |
|:----------|:---------------------------|
| timestamp | 1640450950648              |
| snapshot  | master-snapshot_gen        |
| container | scenario-azure-quick-start |
| test      | master-test.json           |

## Results

### Test ID - PR-AZR-ARM-SQL-046
Title: Ensure SQL server's TDE protector is encrypted with Customer-managed key\
Test Result: **passed**\
Description : Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure's cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.\

#### Test Details
- eval: data.rule.serverKeyType
- id : PR-AZR-ARM-SQL-046

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT530                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers/encryptionprotector', 'microsoft.sql/servers', 'microsoft.resources/deployments', 'microsoft.sql/servers/keys']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: TEST_SQL_SERVER_ENCRYPTION
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_encryption.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/database-new.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT149                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.servicebus/namespaces', 'microsoft.web/sites', 'microsoft.storage/storageaccounts']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT174                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                          |
| type          | arm                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/informatica/informatica-adf-hdinsight-powerbi/nested/sqldatawarehouse.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT220                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/components']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

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
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.insights/autoscalesettings', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgateways']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT333                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT349                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.media/mediaservices', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.storage/storageaccounts']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT520                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/nested/azureDBDeploy.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT530                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers/encryptionprotector', 'microsoft.sql/servers', 'microsoft.resources/deployments', 'microsoft.sql/servers/keys']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT564                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.storage/storageaccounts']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT565                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT631                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.insights/components']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT632                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.insights/components']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT707                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/publicipaddresses', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT786                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privatednszones', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT787                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.sql/servers/databases', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT805                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT870                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-regional-vnet-private-endpoint-sql-storage/nestedtemplates/sqldb.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT875                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT876                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT893                                                                                                                |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                             |
| collection    | armtemplate                                                                                                                             |
| type          | arm                                                                                                                                     |
| region        |                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1218                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1225                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1230                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1251                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.datamigration/services', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1332                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1349                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1355                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.hdinsight/clusters', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1378                                                                                                                         |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-use-dynamic-id/nested/sqlserver.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1680                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privatednszones', 'microsoft.sql/servers/databases', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1681                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1682                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.eventhub/namespaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1683                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1684                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1685                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1686                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1687                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1688                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/elasticpools', 'microsoft.sql/servers', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1689                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1690                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1692                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1693                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1694                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

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

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1755                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.notificationhubs/namespaces/notificationhubs', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1780                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.sql/servers', 'microsoft.managedidentity/userassignedidentities', 'microsoft.authorization/roleassignments', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.sql/servers/firewallrules'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.parameters.json']               |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1784                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.cache/redis']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1785                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites/config', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.sql/servers/firewallrules']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1786                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1798                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-048
Title: Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name\
Test Result: **passed**\
Description : You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.\

#### Test Details
- eval: data.rule.sql_server_login
- id : PR-AZR-ARM-SQL-048

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

- masterTestId: TEST_MSSQL_SERVER_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                                |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-042
Title: Ensure that SQL Server Auditing is Enabled\
Test Result: **passed**\
Description : Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.\

#### Test Details
- eval: data.rule.sql_server_log_audit
- id : PR-AZR-ARM-SQL-042

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT802                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                  |
| type          | arm                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['microsoft.sql/servers/auditingsettings']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.auditingsettings.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-042
Title: Ensure that SQL Server Auditing is Enabled\
Test Result: **passed**\
Description : Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.\

#### Test Details
- eval: data.rule.sql_server_log_audit
- id : PR-AZR-ARM-SQL-042

#### Snapshots
| Title         | Description                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT890                                                                                                                           |
| structure     | filesystem                                                                                                                                         |
| reference     | master                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                        |
| collection    | armtemplate                                                                                                                                        |
| type          | arm                                                                                                                                                |
| region        |                                                                                                                                                    |
| resourceTypes | ['microsoft.sql/servers/auditingsettings']                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.auditingsettings.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-043
Title: Ensure that SQL Server Auditing is Enabled\
Test Result: **passed**\
Description : Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.\

#### Test Details
- eval: data.rule.sql_logical_server_log_audit
- id : PR-AZR-ARM-SQL-043

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1681                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-043
Title: Ensure that SQL Server Auditing is Enabled\
Test Result: **failed**\
Description : Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.\

#### Test Details
- eval: data.rule.sql_logical_server_log_audit
- id : PR-AZR-ARM-SQL-043

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1682                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.eventhub/namespaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-043
Title: Ensure that SQL Server Auditing is Enabled\
Test Result: **failed**\
Description : Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.\

#### Test Details
- eval: data.rule.sql_logical_server_log_audit
- id : PR-AZR-ARM-SQL-043

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1683                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-043
Title: Ensure that SQL Server Auditing is Enabled\
Test Result: **failed**\
Description : Ensure that SQL Server Auditing is enabled in order to keep track of Audit events.\

#### Test Details
- eval: data.rule.sql_logical_server_log_audit
- id : PR-AZR-ARM-SQL-043

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1684                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-044
Title: Azure SQL server audit log retention should be greater than 90 days\
Test Result: **failed**\
Description : Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.\

#### Test Details
- eval: data.rule.sql_server_audit_log_retention
- id : PR-AZR-ARM-SQL-044

#### Snapshots
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT802                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                  |
| type          | arm                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['microsoft.sql/servers/auditingsettings']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.auditingsettings.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-044
Title: Azure SQL server audit log retention should be greater than 90 days\
Test Result: **failed**\
Description : Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.\

#### Test Details
- eval: data.rule.sql_server_audit_log_retention
- id : PR-AZR-ARM-SQL-044

#### Snapshots
| Title         | Description                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT890                                                                                                                           |
| structure     | filesystem                                                                                                                                         |
| reference     | master                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                        |
| collection    | armtemplate                                                                                                                                        |
| type          | arm                                                                                                                                                |
| region        |                                                                                                                                                    |
| resourceTypes | ['microsoft.sql/servers/auditingsettings']                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.auditingsettings.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-045
Title: Azure SQL server audit log retention should be greater than 90 days\
Test Result: **failed**\
Description : Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.\

#### Test Details
- eval: data.rule.sql_logial_server_audit_log_retention
- id : PR-AZR-ARM-SQL-045

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1681                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-045
Title: Azure SQL server audit log retention should be greater than 90 days\
Test Result: **failed**\
Description : Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.\

#### Test Details
- eval: data.rule.sql_logial_server_audit_log_retention
- id : PR-AZR-ARM-SQL-045

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1682                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.eventhub/namespaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-045
Title: Azure SQL server audit log retention should be greater than 90 days\
Test Result: **failed**\
Description : Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.\

#### Test Details
- eval: data.rule.sql_logial_server_audit_log_retention
- id : PR-AZR-ARM-SQL-045

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1683                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-045
Title: Azure SQL server audit log retention should be greater than 90 days\
Test Result: **failed**\
Description : Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access. We recommend you configure SQL server audit retention to be greater than 90 days.\

#### Test Details
- eval: data.rule.sql_logial_server_audit_log_retention
- id : PR-AZR-ARM-SQL-045

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1684                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_SQL_SERVER_AUDITING_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers_auditing.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/database-new.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT149                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.servicebus/namespaces', 'microsoft.web/sites', 'microsoft.storage/storageaccounts']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT174                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                          |
| type          | arm                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/informatica/informatica-adf-hdinsight-powerbi/nested/sqldatawarehouse.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT220                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/components']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

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
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.insights/autoscalesettings', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgateways']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT333                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT349                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.media/mediaservices', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.storage/storageaccounts']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT520                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/nested/azureDBDeploy.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT530                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers/encryptionprotector', 'microsoft.sql/servers', 'microsoft.resources/deployments', 'microsoft.sql/servers/keys']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT564                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.storage/storageaccounts']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT565                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT631                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.insights/components']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT632                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.insights/components']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT707                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/publicipaddresses', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT786                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privatednszones', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT787                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.sql/servers/databases', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT805                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT870                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-regional-vnet-private-endpoint-sql-storage/nestedtemplates/sqldb.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT875                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT876                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT893                                                                                                                |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                             |
| collection    | armtemplate                                                                                                                             |
| type          | arm                                                                                                                                     |
| region        |                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1218                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1225                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1230                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1251                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.datamigration/services', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1332                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1349                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1355                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.hdinsight/clusters', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1378                                                                                                                         |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-use-dynamic-id/nested/sqlserver.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1680                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privatednszones', 'microsoft.sql/servers/databases', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1681                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1682                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.eventhub/namespaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1683                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1684                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1685                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1686                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1687                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1688                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/elasticpools', 'microsoft.sql/servers', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1689                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1690                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1692                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **passed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1693                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **passed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1694                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

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

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1755                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.notificationhubs/namespaces/notificationhubs', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1780                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.sql/servers', 'microsoft.managedidentity/userassignedidentities', 'microsoft.authorization/roleassignments', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.sql/servers/firewallrules'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.parameters.json']               |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1784                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.cache/redis']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1785                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites/config', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.sql/servers/firewallrules']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1786                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-050
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-ARM-SQL-050

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1798                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                    |
|:-----------|:---------------------------------------------------------------|
| cloud      | git                                                            |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['arm']                                                        |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/database-new.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT149                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.servicebus/namespaces', 'microsoft.web/sites', 'microsoft.storage/storageaccounts']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT174                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                          |
| type          | arm                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/informatica/informatica-adf-hdinsight-powerbi/nested/sqldatawarehouse.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT220                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/components']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

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
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.insights/autoscalesettings', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgateways']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT333                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT349                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.media/mediaservices', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.storage/storageaccounts']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT520                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/nested/azureDBDeploy.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT530                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers/encryptionprotector', 'microsoft.sql/servers', 'microsoft.resources/deployments', 'microsoft.sql/servers/keys']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT564                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.storage/storageaccounts']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT565                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT631                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.insights/components']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT632                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.insights/components']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT707                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/publicipaddresses', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT786                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privatednszones', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT787                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.sql/servers/databases', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT805                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT870                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-regional-vnet-private-endpoint-sql-storage/nestedtemplates/sqldb.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT875                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT876                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT893                                                                                                                |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                             |
| collection    | armtemplate                                                                                                                             |
| type          | arm                                                                                                                                     |
| region        |                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1218                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1225                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1230                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1251                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.datamigration/services', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1332                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1349                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1355                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.hdinsight/clusters', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1378                                                                                                                         |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-use-dynamic-id/nested/sqlserver.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1680                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privatednszones', 'microsoft.sql/servers/databases', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1681                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1682                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.eventhub/namespaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1683                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1684                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1685                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1686                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1687                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1688                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/elasticpools', 'microsoft.sql/servers', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1689                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1690                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1692                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1693                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1694                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

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

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1755                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.notificationhubs/namespaces/notificationhubs', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1780                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.sql/servers', 'microsoft.managedidentity/userassignedidentities', 'microsoft.authorization/roleassignments', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.sql/servers/firewallrules'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.parameters.json']               |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1784                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.cache/redis']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1785                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites/config', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.sql/servers/firewallrules']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1786                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-069
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1798                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/database-new.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT149                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.servicebus/namespaces', 'microsoft.web/sites', 'microsoft.storage/storageaccounts']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT174                                                                                                                                             |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                          |
| type          | arm                                                                                                                                                                  |
| region        |                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/informatica/informatica-adf-hdinsight-powerbi/nested/sqldatawarehouse.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT220                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/components']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

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
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.insights/autoscalesettings', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgateways']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT333                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT349                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.media/mediaservices', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.storage/storageaccounts']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT520                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/nested/azureDBDeploy.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT530                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers/encryptionprotector', 'microsoft.sql/servers', 'microsoft.resources/deployments', 'microsoft.sql/servers/keys']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT564                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.storage/storageaccounts']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT565                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT631                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.insights/components']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT632                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.insights/components']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT707                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/publicipaddresses', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT786                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privatednszones', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT787                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.sql/servers/databases', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT805                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT870                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-regional-vnet-private-endpoint-sql-storage/nestedtemplates/sqldb.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT875                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT876                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT893                                                                                                                |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                             |
| collection    | armtemplate                                                                                                                             |
| type          | arm                                                                                                                                     |
| region        |                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1218                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1225                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1230                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1251                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.datamigration/services', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1332                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1349                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1355                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.hdinsight/clusters', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1378                                                                                                                         |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-use-dynamic-id/nested/sqlserver.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1680                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privatednszones', 'microsoft.sql/servers/databases', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1681                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1682                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.eventhub/namespaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1683                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1684                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1685                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1686                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1687                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1688                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/elasticpools', 'microsoft.sql/servers', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1689                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1690                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1692                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1693                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1694                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

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

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1755                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.notificationhubs/namespaces/notificationhubs', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1780                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.sql/servers', 'microsoft.managedidentity/userassignedidentities', 'microsoft.authorization/roleassignments', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.sql/servers/firewallrules'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.parameters.json']               |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1784                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.cache/redis']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1785                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites/config', 'microsoft.sql/servers/databases', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.sql/servers/firewallrules']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1786                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-070
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-070

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1798                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_5
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------

