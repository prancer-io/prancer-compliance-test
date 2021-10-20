# Automated Vulnerability Scan result and Static Code Analysis for Azure Quickstart files (Oct 2021)


## Azure SQL Servers Services

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

### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.servicebus/namespaces']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.media/mediaservices', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.sql/servers/encryptionprotector', 'microsoft.sql/servers', 'microsoft.sql/servers/keys']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.cache/redis', 'microsoft.insights/metricalerts', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT630                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.sql/servers', 'microsoft.insights/metricalerts', 'microsoft.insights/components', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT631                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.sql/servers', 'microsoft.insights/metricalerts', 'microsoft.insights/components', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT785                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers/databases', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/sites', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT786                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers/databases', 'microsoft.network/loadbalancers', 'microsoft.resources/deployments'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT804                                                                                                                          |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT869                                                                                                                                |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT874                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.search/searchservices']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT875                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.search/searchservices']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT892                                                                                                                |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1213                                                                                                                                                                                                                                                                                                                                                                                         |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1220                                                                                                                                                                                                                                                                                                                               |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1225                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1246                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.datamigration/services', 'microsoft.compute/virtualmachines']                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1328                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1345                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1351                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.hdinsight/clusters']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1373                                                                                                                         |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1664                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers/databases', 'microsoft.network/privatednszones', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1665                                                                                                                                                                                                                                                                                                     |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1666                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.eventhub/namespaces']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1667                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1668                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1669                                                                                                                                                                                                                                                                                                                 |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1670                                                                                                                                                                                                                                         |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1671                                                                                                                                                                                                                                                                                                     |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1672                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/firewallrules', 'microsoft.sql/servers', 'microsoft.sql/servers/elasticpools', 'microsoft.sql/servers/databases']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1673                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1674                                                                                                                                                                                                                                                                                 |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1676                                                                                                                                                                                                                                                                                                                   |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1677                                                                                                                                                                                                                                                               |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1678                                                                                                                                                                                                                                                                  |
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
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

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

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1735                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.notificationhubs/namespaces', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.notificationhubs/namespaces/notificationhubs', 'microsoft.web/sites']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1763                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.cache/redis', 'microsoft.web/serverfarms']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1764                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers/firewallrules']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1765                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0128-ARM
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1777                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.web/serverfarms']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-0133-ARM
Title: Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name\
Test Result: **passed**\
Description : You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.\

#### Test Details
- eval: data.rule.sql_server_login
- id : PR-AZR-0133-ARM

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

- masterTestId: TEST_MSSQL_SERVER_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.servicebus/namespaces']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.media/mediaservices', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.sql/servers/encryptionprotector', 'microsoft.sql/servers', 'microsoft.sql/servers/keys']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.cache/redis', 'microsoft.insights/metricalerts', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT630                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.sql/servers', 'microsoft.insights/metricalerts', 'microsoft.insights/components', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT631                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.sql/servers', 'microsoft.insights/metricalerts', 'microsoft.insights/components', 'microsoft.insights/actiongroups', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT785                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers/databases', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/sites', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT786                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers/databases', 'microsoft.network/loadbalancers', 'microsoft.resources/deployments'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT804                                                                                                                          |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT869                                                                                                                                |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT874                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.search/searchservices']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT875                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.documentdb/databaseaccounts', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.search/searchservices']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT892                                                                                                                |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1213                                                                                                                                                                                                                                                                                                                                                                                         |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1220                                                                                                                                                                                                                                                                                                                               |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1225                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1246                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.datamigration/services', 'microsoft.compute/virtualmachines']                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datamigration/azure-database-migration-service/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1328                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1345                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1351                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.hdinsight/clusters']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1373                                                                                                                         |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1664                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers/databases', 'microsoft.network/privatednszones', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1665                                                                                                                                                                                                                                                                                                     |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1666                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.eventhub/namespaces']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1667                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1668                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1669                                                                                                                                                                                                                                                                                                                 |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1670                                                                                                                                                                                                                                         |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1671                                                                                                                                                                                                                                                                                                     |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1672                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/firewallrules', 'microsoft.sql/servers', 'microsoft.sql/servers/elasticpools', 'microsoft.sql/servers/databases']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1673                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1674                                                                                                                                                                                                                                                                                 |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1676                                                                                                                                                                                                                                                                                                                   |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **passed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1677                                                                                                                                                                                                                                                               |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **passed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1678                                                                                                                                                                                                                                                                  |
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
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

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

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1735                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.notificationhubs/namespaces', 'microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.notificationhubs/namespaces/notificationhubs', 'microsoft.web/sites']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1763                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.cache/redis', 'microsoft.web/serverfarms']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1764                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers/firewallrules']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1765                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0190-ARM
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1777                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.web/serverfarms']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: TEST_MSSQL_SERVER_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['PCI-DSS', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-0191-ARM
Title: Ensure that Azure Active Directory Admin is configured for SQL Server.\
Test Result: **passed**\
Description : Use Azure Active Directory Authentication for authentication with SQL Databases. Azure Active Directory authentication is a mechanism of connecting Microsoft Azure SQL Databases and SQL Data Warehouses using identities in an Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.\

#### Test Details
- eval: data.rule.sql_server_administrators
- id : PR-AZR-0191-ARM

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

- masterTestId: TEST_MSSQL_SERVER_4
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_servers.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------

