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

## Azure PostgreSQL Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description               |
|:----------|:--------------------------|
| timestamp | 1642958430464             |
| snapshot  | master-snapshot_gen       |
| container | scenario-azure-quickStart |
| test      | master-test.json          |

## Results

### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT22                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/airflow-postgres-app-services/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/airflow-postgres-app-services/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT44                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbformysql/servers', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/buffalo/gobuffalo/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/buffalo/gobuffalo/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **passed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT240                                                                                                                     |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                  |
| collection    | armtemplate                                                                                                                                  |
| type          | arm                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['microsoft.dbforpostgresql/servers']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mahara/mahara-autoscale-cache/nested/postgres.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT299                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                          |
| collection    | armtemplate                                                                                                                                          |
| type          | arm                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['microsoft.dbforpostgresql/servers']                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/moodle/moodle-scalable-cluster-ubuntu/nested/postgres.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1227                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.dbforpostgresql/servers']                                                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-postgresql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-postgresql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1266                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.dbforpostgresql/servers/firewallrules', 'microsoft.network/virtualnetworks', 'microsoft.dbforpostgresql/servers', 'microsoft.network/virtualnetworks/subnets', 'microsoft.dbforpostgresql/servers/virtualnetworkrules']                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.dbforpostgresql/managed-postgresql-with-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.dbforpostgresql/managed-postgresql-with-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1803                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-airflow-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-airflow-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1807                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-managed-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-managed-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1811                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-ARM-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1813                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-managed-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-managed-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-028
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT22                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/airflow-postgres-app-services/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/airflow-postgres-app-services/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT44                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbformysql/servers', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/buffalo/gobuffalo/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/buffalo/gobuffalo/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT240                                                                                                                     |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                  |
| collection    | armtemplate                                                                                                                                  |
| type          | arm                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['microsoft.dbforpostgresql/servers']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mahara/mahara-autoscale-cache/nested/postgres.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT299                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                          |
| collection    | armtemplate                                                                                                                                          |
| type          | arm                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['microsoft.dbforpostgresql/servers']                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/moodle/moodle-scalable-cluster-ubuntu/nested/postgres.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1227                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.dbforpostgresql/servers']                                                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-postgresql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-postgresql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1266                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.dbforpostgresql/servers/firewallrules', 'microsoft.network/virtualnetworks', 'microsoft.dbforpostgresql/servers', 'microsoft.network/virtualnetworks/subnets', 'microsoft.dbforpostgresql/servers/virtualnetworkrules']                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.dbforpostgresql/managed-postgresql-with-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.dbforpostgresql/managed-postgresql-with-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1803                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-airflow-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-airflow-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1807                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-managed-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-managed-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1811                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **failed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-ARM-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1813                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-managed-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-managed-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-029
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT22                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/airflow-postgres-app-services/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/airflow-postgres-app-services/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT44                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbformysql/servers', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/buffalo/gobuffalo/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/buffalo/gobuffalo/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT240                                                                                                                     |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                  |
| collection    | armtemplate                                                                                                                                  |
| type          | arm                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['microsoft.dbforpostgresql/servers']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mahara/mahara-autoscale-cache/nested/postgres.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT299                                                                                                                             |
| structure     | filesystem                                                                                                                                           |
| reference     | master                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                          |
| collection    | armtemplate                                                                                                                                          |
| type          | arm                                                                                                                                                  |
| region        |                                                                                                                                                      |
| resourceTypes | ['microsoft.dbforpostgresql/servers']                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/moodle/moodle-scalable-cluster-ubuntu/nested/postgres.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1227                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.dbforpostgresql/servers']                                                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-postgresql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-postgresql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1266                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.dbforpostgresql/servers/firewallrules', 'microsoft.network/virtualnetworks', 'microsoft.dbforpostgresql/servers', 'microsoft.network/virtualnetworks/subnets', 'microsoft.dbforpostgresql/servers/virtualnetworkrules']                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.dbforpostgresql/managed-postgresql-with-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.dbforpostgresql/managed-postgresql-with-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1803                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-airflow-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-airflow-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1807                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-managed-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-managed-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1811                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-ARM-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1813                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/sites', 'microsoft.dbforpostgresql/servers', 'microsoft.web/serverfarms']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-managed-postgresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-managed-postgresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-066
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------

