# Automated Vulnerability Scan result and Static Code Analysis for Azure Quickstart files (Aug 2021)


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
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.hdinsight/clusters', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                          |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT41                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT152                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT155                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT156                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT157                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT158                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT159                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.operationalinsights/workspaces', 'microsoft.sql/servers']                                                                                                                                                                                                                                          |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT161                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT162                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                             |
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
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT163                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/privateendpoints', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers/databases'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT164                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT165                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/elasticpools', 'microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT166                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT167                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                          |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT438                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.datamigration/services', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.network/networkinterfaces']                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT485                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT502                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                 |
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
| id            | ARM_TEMPLATE_SNAPSHOT507                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT701                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces']                                          |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT709                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers']                                                                                                                                                                                                    |
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
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT713                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers']                                                                                                                                                                                                                           |
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
| id            | ARM_TEMPLATE_SNAPSHOT724                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces', 'microsoft.sql/servers', 'microsoft.notificationhubs/namespaces/notificationhubs']                                                                                            |
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
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT730                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers/firewallrules', 'microsoft.web/sites/config', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                            |
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
| id            | ARM_TEMPLATE_SNAPSHOT862                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                 |
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
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT880                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT917                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.web/sites', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/privateendpoints', 'microsoft.sql/servers/databases'] |
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
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT934                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.insights/autoscalesettings']               |
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
| id            | ARM_TEMPLATE_SNAPSHOT935                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.insights/autoscalesettings']                  |
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
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-0128-ARM

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT956                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT1030                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.search/searchservices', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.documentdb/databaseaccounts']                   |
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
| id            | ARM_TEMPLATE_SNAPSHOT1031                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.search/searchservices', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.documentdb/databaseaccounts']                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1081                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/loadbalancers', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers/databases'] |
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
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1103                                                                                                               |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT1213                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                                            |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1328                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1343                                                                                                                                            |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                                                    |
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1390                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.servicebus/namespaces', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                             |
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
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1415                                                                                                                        |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorArmMS                                                                                                                                |
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
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.cache/redis', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.insights/actiongroups', 'microsoft.insights/autoscalesettings']                                                     |
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
| id            | ARM_TEMPLATE_SNAPSHOT1420                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.insights/autoscalesettings']                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1426                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.sql/servers/keys', 'microsoft.sql/servers', 'microsoft.sql/servers/encryptionprotector']                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1676                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings']                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1725                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                      |
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
| id            | ARM_TEMPLATE_SNAPSHOT1780                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.media/mediaservices', 'microsoft.web/sites', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                               |
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
| id            | ARM_TEMPLATE_SNAPSHOT751                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints', 'microsoft.web/hostingenvironments', 'microsoft.web/serverfarms', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworkgateways', 'microsoft.web/sites/config', 'microsoft.storage/storageaccounts', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT19                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                           |
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
| id            | ARM_TEMPLATE_SNAPSHOT41                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT152                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT155                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT156                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT157                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT158                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                           |
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
| id            | ARM_TEMPLATE_SNAPSHOT159                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                              |
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
| id            | ARM_TEMPLATE_SNAPSHOT161                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                           |
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
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT162                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT163                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/privateendpoints', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers/databases'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT164                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT165                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/elasticpools', 'microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                               |
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
Test Result: **passed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: data.rule.fail_over_groups
- id : PR-AZR-0190-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT166                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT167                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                          |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT438                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.datamigration/services', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers', 'microsoft.network/networkinterfaces']                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT485                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT502                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                 |
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
| id            | ARM_TEMPLATE_SNAPSHOT507                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT701                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces']                                          |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT709                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.cache/redis', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.sql/servers']                                                                                                                                                                                                    |
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
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT713                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT724                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces', 'microsoft.sql/servers', 'microsoft.notificationhubs/namespaces/notificationhubs']                                                                                            |
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
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT730                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers/firewallrules', 'microsoft.web/sites/config', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                            |
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
| id            | ARM_TEMPLATE_SNAPSHOT862                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                 |
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
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT880                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT917                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.web/sites', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/privateendpoints', 'microsoft.sql/servers/databases'] |
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
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT934                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.insights/autoscalesettings']               |
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
| id            | ARM_TEMPLATE_SNAPSHOT935                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/actiongroups', 'microsoft.insights/autoscalesettings']                  |
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
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT956                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT1030                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.search/searchservices', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.documentdb/databaseaccounts']                   |
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
| id            | ARM_TEMPLATE_SNAPSHOT1031                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.search/searchservices', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.documentdb/databaseaccounts']                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1081                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/loadbalancers', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers/databases'] |
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
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1103                                                                                                               |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT1213                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                                            |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1328                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1343                                                                                                                                            |
| structure     | filesystem                                                                                                                                                           |
| reference     | master                                                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                                                    |
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1390                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.servicebus/namespaces', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                             |
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
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1415                                                                                                                        |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorArmMS                                                                                                                                |
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
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/metricalerts', 'microsoft.cache/redis', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.insights/actiongroups', 'microsoft.insights/autoscalesettings']                                                     |
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
| id            | ARM_TEMPLATE_SNAPSHOT1420                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.insights/autoscalesettings']                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1426                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.sql/servers/keys', 'microsoft.sql/servers', 'microsoft.sql/servers/encryptionprotector']                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1676                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings']                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1725                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                      |
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
| id            | ARM_TEMPLATE_SNAPSHOT1780                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.media/mediaservices', 'microsoft.web/sites', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                               |
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
| id            | ARM_TEMPLATE_SNAPSHOT751                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints', 'microsoft.web/hostingenvironments', 'microsoft.web/serverfarms', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworkgateways', 'microsoft.web/sites/config', 'microsoft.storage/storageaccounts', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces'] |
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

