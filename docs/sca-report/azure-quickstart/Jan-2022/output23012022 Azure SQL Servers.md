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

## Azure SQL Servers Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description               |
|:----------|:--------------------------|
| timestamp | 1642960966581             |
| snapshot  | master-snapshot_gen       |
| container | scenario-azure-quickStart |
| test      | master-test.json          |

## Results

### Test ID - 
Title: Ensure Security Alert is enabled on Azure SQL Logical Server\
Test Result: **failed**\
Description : Advanced data security should be enabled on your SQL servers.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-030', 'eval': 'data.rule.sql_logical_server_alert', 'message': 'data.rule.sql_logical_server_alert_err', 'remediationDescription': "Make sure you are following the ARM template guidelines for vpn gateway by visiting <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a>", 'remediationFunction': 'PR_AZR_ARM_SQL_030.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-030
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: Medium

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-030
Title: Ensure Security Alert is enabled on Azure SQL Logical Server\
Test Result: **passed**\
Description : Advanced data security should be enabled on your SQL servers.\

#### Test Details
- eval: data.rule.sql_logical_server_alert
- id : PR-AZR-ARM-SQL-030

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1699                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-030
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: Medium

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-030
Title: Ensure Security Alert is enabled on Azure SQL Logical Server\
Test Result: **passed**\
Description : Advanced data security should be enabled on your SQL servers.\

#### Test Details
- eval: data.rule.sql_logical_server_alert
- id : PR-AZR-ARM-SQL-030

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1702                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-030
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: Medium

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-031
Title: Ensure Security Alert is enabled on Azure SQL Server\
Test Result: **passed**\
Description : Advanced data security should be enabled on your SQL servers.\

#### Test Details
- eval: data.rule.sql_server_alert
- id : PR-AZR-ARM-SQL-031

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT806                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                       |
| type          | arm                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-031
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: Medium

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-031
Title: Ensure Security Alert is enabled on Azure SQL Server\
Test Result: **passed**\
Description : Advanced data security should be enabled on your SQL servers.\

#### Test Details
- eval: data.rule.sql_server_alert
- id : PR-AZR-ARM-SQL-031

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT894                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-031
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: Medium

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Ensure Security Alert is enabled on Azure SQL Server\
Test Result: **failed**\
Description : Advanced data security should be enabled on your SQL servers.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-031', 'eval': 'data.rule.sql_server_alert', 'message': 'data.rule.sql_server_alert_err', 'remediationDescription': 'In Resource of type "Microsoft.sql/servers/securityalertpolicies" make sure properties.state exists and value is set to "Enabled" .<br>Please visit <a href=\'https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies\' target=\'_blank\'>here</a>', 'remediationFunction': 'PR_AZR_ARM_SQL_031.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-031
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: Medium

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Ensure Security Alert is enabled on Azure SQL Managed Instance\
Test Result: **failed**\
Description : Advanced data security should be enabled on your SQL managed instance.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-032', 'eval': 'data.rule.sql_managed_instance_alert', 'message': 'data.rule.sql_managed_instance_alert_err', 'remediationDescription': 'In Resource of type "Microsoft.sql/managedinstances/securityalertpolicies" make sure properties.state exists and value is set to "Enabled" .<br>Please visit <a href=\'https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/securityalertpolicies\' target=\'_blank\'>here</a>', 'remediationFunction': 'PR_AZR_ARM_SQL_032.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-032
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: Medium

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Ensure SQL Server administrator login does not contain 'Admin/Administrator' as name\
Test Result: **failed**\
Description : You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-048', 'eval': 'data.rule.sql_server_login', 'message': 'data.rule.sql_server_login_err', 'remediationDescription': 'In Resource of type "Microsoft.Sql/servers/administrators" make sure properties.login value isn\'t set to "admin" or "administrator" .<br>Please visit <a href=\'https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/administrators\' target=\'_blank\'>here</a> for details.', 'remediationFunction': 'PR_AZR_ARM_SQL_048.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-048
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


### Test ID - PR-AZR-ARM-SQL-048
Title: Ensure SQL Server administrator login does not contain 'Admin/Administrator' as name\
Test Result: **passed**\
Description : You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.\

#### Test Details
- eval: data.rule.sql_server_login
- id : PR-AZR-ARM-SQL-048

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworkgateways', 'microsoft.sql/servers', 'microsoft.web/hostingenvironments', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites', 'microsoft.compute/virtualmachines', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: PR-AZR-ARM-SQL-048
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

- masterTestId: PR-AZR-ARM-SQL-050
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
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.servicebus/namespaces', 'microsoft.web/sites']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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

- masterTestId: PR-AZR-ARM-SQL-050
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
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/loadbalancers', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.media/mediaservices', 'microsoft.sql/servers', 'microsoft.web/sites']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT522                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/nested/azureDBDeploy.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT532                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers/keys', 'microsoft.sql/servers', 'microsoft.sql/servers/encryptionprotector', 'microsoft.resources/deployments']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT566                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.cache/redis', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/actiongroups']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT567                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT633                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/actiongroups']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT634                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/actiongroups']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT709                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.cache/redis', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.cdn/profiles'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT788                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers/databases', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/sites', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT789                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.sql/servers/databases', 'microsoft.resources/deployments', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT807                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT872                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-regional-vnet-private-endpoint-sql-storage/nestedtemplates/sqldb.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT877                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT878                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT895                                                                                                                |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                             |
| collection    | armtemplate                                                                                                                             |
| type          | arm                                                                                                                                     |
| region        |                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1222                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1229                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1234                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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


### Test ID - 
Title: Ensure Azure SQL Server data replication with Fail Over groups\
Test Result: **failed**\
Description : SQL Server data should be replicated to avoid loss of unreplicated data.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-050', 'eval': 'data.rule.fail_over_groups', 'message': 'data.rule.fail_over_groups_err', 'remediationDescription': "For Resource type 'microsoft.sql/servers' make sure has a subresource with type 'failoverGroups'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/failovergroups' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_050.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1336                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1353                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1359                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.hdinsight/clusters', 'microsoft.sql/servers']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1382                                                                                                                         |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-use-dynamic-id/nested/sqlserver.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1690                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.sql/servers/databases', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1691                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1692                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.eventhub/namespaces']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1693                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1694                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1695                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.sql/servers/databases/transparentdataencryption']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1696                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1697                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1698                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.sql/servers/elasticpools', 'microsoft.sql/servers/firewallrules']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1699                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1700                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1702                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1703                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1704                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1745                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworkgateways', 'microsoft.sql/servers', 'microsoft.web/hostingenvironments', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites', 'microsoft.compute/virtualmachines', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1765                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.notificationhubs/namespaces', 'microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces/notificationhubs']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1791                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.web/serverfarms', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases', 'microsoft.managedidentity/userassignedidentities', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.parameters.json']               |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1795                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.cache/redis', 'microsoft.web/sites']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1796                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1797                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
| id            | ARM_TEMPLATE_SNAPSHOT1809                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-050
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

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

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

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
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.servicebus/namespaces', 'microsoft.web/sites']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

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

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

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
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

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
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/loadbalancers', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

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
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.media/mediaservices', 'microsoft.sql/servers', 'microsoft.web/sites']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT522                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/nested/azureDBDeploy.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT532                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers/keys', 'microsoft.sql/servers', 'microsoft.sql/servers/encryptionprotector', 'microsoft.resources/deployments']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT566                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.cache/redis', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/actiongroups']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT567                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT633                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/actiongroups']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT634                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/actiongroups']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.cache/redis', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.cdn/profiles'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT788                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers/databases', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/sites', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT789                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.sql/servers/databases', 'microsoft.resources/deployments', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT807                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT872                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-regional-vnet-private-endpoint-sql-storage/nestedtemplates/sqldb.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT877                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT878                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT895                                                                                                                |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                             |
| collection    | armtemplate                                                                                                                             |
| type          | arm                                                                                                                                     |
| region        |                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1222                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1229                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1234                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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


### Test ID - 
Title: Ensure Azure SQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-069', 'eval': 'data.rule.sql_server_latest_tls_configured', 'message': 'data.rule.sql_server_latest_tls_configured_err', 'remediationDescription': "In 'microsoft.sql/servers' resource, set 'minimalTlsVersion = 1.2' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_ARM_SQL_069.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1336                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1353                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1359                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.hdinsight/clusters', 'microsoft.sql/servers']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1382                                                                                                                         |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-use-dynamic-id/nested/sqlserver.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1690                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.sql/servers/databases', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1691                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1692                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.eventhub/namespaces']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1693                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1694                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1695                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.sql/servers/databases/transparentdataencryption']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1696                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1697                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1698                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.sql/servers/elasticpools', 'microsoft.sql/servers/firewallrules']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1699                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1700                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1702                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1703                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1704                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworkgateways', 'microsoft.sql/servers', 'microsoft.web/hostingenvironments', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites', 'microsoft.compute/virtualmachines', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1765                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.notificationhubs/namespaces', 'microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces/notificationhubs']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1791                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.web/serverfarms', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases', 'microsoft.managedidentity/userassignedidentities', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.parameters.json']               |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1795                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.cache/redis', 'microsoft.web/sites']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1796                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1797                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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
Description : This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert\

#### Test Details
- eval: data.rule.sql_server_latest_tls_configured
- id : PR-AZR-ARM-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1809                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-069
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
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

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
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
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.servicebus/namespaces', 'microsoft.web/sites']                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/episerver/episerver-cms-in-azure/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
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

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
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
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kentico/kentico-xperience-environment/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
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
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/loadbalancers', 'microsoft.network/publicipaddresses', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
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
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.media/mediaservices', 'microsoft.sql/servers', 'microsoft.web/sites']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/orchard/orchard-cms-video-portal/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT522                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/nested/azureDBDeploy.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT532                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers/keys', 'microsoft.sql/servers', 'microsoft.sql/servers/encryptionprotector', 'microsoft.resources/deployments']                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sql-encryption-protector-byok/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT566                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.cache/redis', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.web/sites', 'microsoft.insights/actiongroups']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-cms-webapp-redis-cache/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT567                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/umbraco/umbraco-webapp-simple/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT633                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/actiongroups']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT634                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.insights/metricalerts', 'microsoft.sql/servers', 'microsoft.insights/autoscalesettings', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.insights/actiongroups']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azure-governance-operations-automation/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.cache/redis', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.cdn/profiles'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT788                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers/databases', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/sites', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-endpoint-sql-from-appservice/azuredeploy.parameters.json']                                                                            |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT789                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.sql/servers/databases', 'microsoft.resources/deployments', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/rds-deployment-full-ha/azuredeploy.parameters.json']                                                  |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT807                                                                                                                          |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT872                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-regional-vnet-private-endpoint-sql-storage/nestedtemplates/sqldb.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT877                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT878                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.web/serverfarms', 'microsoft.search/searchservices', 'microsoft.documentdb/databaseaccounts', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/web-app-sql-docdb-search/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT895                                                                                                                |
| structure     | filesystem                                                                                                                              |
| reference     | master                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                             |
| collection    | armtemplate                                                                                                                             |
| type          | arm                                                                                                                                     |
| region        |                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.v12.0.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1222                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-azure-sql-database-to-sql-data-warehouse-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1229                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-blob-to-sql-copy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1234                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.datafactory/data-factory-v2-provision-ssis-runtime/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - 
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-047', 'eval': 'data.rule.sql_public_access', 'message': 'data.rule.sql_public_access_err', 'remediationDescription': "In 'microsoft.sql/servers' resource, set 'publicNetworkAccess = Disabled' to fix the issue.<br>Please Visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_ARM_SQL_047.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1336                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-custom-ambari-db/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1353                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-ssh-publickey-metastore-vnet/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1359                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.hdinsight/clusters', 'microsoft.sql/servers']                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.hdinsight/hdinsight-linux-with-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1382                                                                                                                         |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-use-dynamic-id/nested/sqlserver.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1690                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.sql/servers/databases', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/private-endpoint-sql/azuredeploy.parameters.json']                                                                                                                                   |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1691                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.sql/servers']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-blob-storage/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1692                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.eventhub/namespaces']                                                                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-eventhub/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1693                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1694                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.operationalinsights/workspaces']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-auditing-server-policy-to-oms/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1695                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.sql/servers/databases/transparentdataencryption']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-data-warehouse-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1696                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1697                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-database-transparent-encryption-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1698                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.sql/servers/elasticpools', 'microsoft.sql/servers/firewallrules']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-elastic-pool-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1699                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1700                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server-aad-only-auth/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1702                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1703                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1704                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.sql/servers']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-with-failover-group/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

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
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworkgateways', 'microsoft.sql/servers', 'microsoft.web/hostingenvironments', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites', 'microsoft.compute/virtualmachines', 'microsoft.network/privateendpoints'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1765                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.notificationhubs/namespaces', 'microsoft.sql/servers', 'microsoft.web/sites', 'microsoft.notificationhubs/namespaces/notificationhubs']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/mobile-app-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1791                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.web/serverfarms', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases', 'microsoft.managedidentity/userassignedidentities', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-managed-identity-sql-db/azuredeploy.parameters.json']               |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1795                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.cache/redis', 'microsoft.web/sites']                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-redis-cache-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1796                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.sql/servers/firewallrules', 'microsoft.sql/servers/databases', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/sites/config', 'microsoft.web/sites']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-sql-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1797                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-vm-dsc/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - PR-AZR-ARM-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for Azure SQL Database and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access
- id : PR-AZR-ARM-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1809                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/webapp-linux-sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-047
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


### Test ID - 
Title: Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server\
Test Result: **failed**\
Description : VA scan reports and alerts will be sent to admins and subscription owners by enabling the setting 'Also send email notifications to admins and subscription owners'. This may help in reducing the time required for identifying risks and taking corrective measures.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-033', 'eval': 'data.rule.sql_logical_server_email_account', 'message': 'data.rule.sql_logical_server_email_account_err', 'remediationDescription': "For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.emailAccountAdmins exists and the value is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_033.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-033
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-033
Title: Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server\
Test Result: **passed**\
Description : VA scan reports and alerts will be sent to admins and subscription owners by enabling the setting 'Also send email notifications to admins and subscription owners'. This may help in reducing the time required for identifying risks and taking corrective measures.\

#### Test Details
- eval: data.rule.sql_logical_server_email_account
- id : PR-AZR-ARM-SQL-033

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1699                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-033
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-034
Title: Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server\
Test Result: **failed**\
Description : VA scan reports and alerts will be sent to admins and subscription owners by enabling the setting 'Also send email notifications to admins and subscription owners'. This may help in reducing the time required for identifying risks and taking corrective measures.\

#### Test Details
- eval: data.rule.sql_server_email_account
- id : PR-AZR-ARM-SQL-034

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT806                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                       |
| type          | arm                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-034
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-034
Title: Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server\
Test Result: **failed**\
Description : VA scan reports and alerts will be sent to admins and subscription owners by enabling the setting 'Also send email notifications to admins and subscription owners'. This may help in reducing the time required for identifying risks and taking corrective measures.\

#### Test Details
- eval: data.rule.sql_server_email_account
- id : PR-AZR-ARM-SQL-034

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT894                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-034
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Ensure that VA setting 'Also send email notifications to admins and subscription owners' is set for a SQL server\
Test Result: **failed**\
Description : VA scan reports and alerts will be sent to admins and subscription owners by enabling the setting 'Also send email notifications to admins and subscription owners'. This may help in reducing the time required for identifying risks and taking corrective measures.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-034', 'eval': 'data.rule.sql_server_email_account', 'message': 'data.rule.sql_server_email_account_err', 'remediationDescription': "For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.emailAccountAdmins exists and the value is set to true.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_034.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-034
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses\
Test Result: **failed**\
Description : Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-035', 'eval': 'data.rule.sql_logical_server_email_addressess', 'message': 'data.rule.sql_logical_server_email_addressess_err', 'remediationDescription': "For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.emailAddresses exists and has a valid email address.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_035.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-035
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-035
Title: Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses\
Test Result: **failed**\
Description : Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.\

#### Test Details
- eval: data.rule.sql_logical_server_email_addressess
- id : PR-AZR-ARM-SQL-035

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1699                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-035
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-035
Title: Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses\
Test Result: **passed**\
Description : Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.\

#### Test Details
- eval: data.rule.sql_logical_server_email_addressess
- id : PR-AZR-ARM-SQL-035

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1702                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-035
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-036
Title: Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses\
Test Result: **passed**\
Description : Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.\

#### Test Details
- eval: data.rule.sql_server_email_addressess
- id : PR-AZR-ARM-SQL-036

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT806                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                       |
| type          | arm                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-036
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-036
Title: Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses\
Test Result: **passed**\
Description : Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.\

#### Test Details
- eval: data.rule.sql_server_email_addressess
- id : PR-AZR-ARM-SQL-036

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT894                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-036
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Azure SQL Security Alert Policy should be configured to send alerts to the account administrators and configured email addresses\
Test Result: **failed**\
Description : Provide the email address where alerts will be sent when anomalous activities are detected on SQL servers.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-036', 'eval': 'data.rule.sql_server_email_addressess', 'message': 'data.rule.sql_server_email_addressess_err', 'remediationDescription': "For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.emailAddresses exists and has a valid email address.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_036.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-036
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days\
Test Result: **failed**\
Description : Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-037', 'eval': 'data.rule.sql_logical_server_retention_days', 'message': 'data.rule.sql_logical_server_retention_days_err', 'remediationDescription': "For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.retentionDays exists and the value is set to greater than 90.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_037.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-037
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-037
Title: Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days\
Test Result: **failed**\
Description : Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.\

#### Test Details
- eval: data.rule.sql_logical_server_retention_days
- id : PR-AZR-ARM-SQL-037

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1699                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-037
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-037
Title: Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days\
Test Result: **failed**\
Description : Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.\

#### Test Details
- eval: data.rule.sql_logical_server_retention_days
- id : PR-AZR-ARM-SQL-037

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1702                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.sql/servers/databases']                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-threat-detection-db-policy-multiple-databases/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-037
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-038
Title: Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days\
Test Result: **passed**\
Description : Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.\

#### Test Details
- eval: data.rule.sql_server_retention_days
- id : PR-AZR-ARM-SQL-038

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT806                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                       |
| type          | arm                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-038
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-038
Title: Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days\
Test Result: **passed**\
Description : Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.\

#### Test Details
- eval: data.rule.sql_server_retention_days
- id : PR-AZR-ARM-SQL-038

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT894                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-038
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Ensure SQL Server Threat Detection is Enabled and Retention Logs are greater than 90 days\
Test Result: **failed**\
Description : Azure SQL Database Threat Detection is a security intelligence feature built into the Azure SQL Database service. Working around the clock to learn, profile and detect anomalous database activities, Azure SQL Database Threat Detection identifies potential threats to the database. Security officers or other designated administrators can get an immediate notification about suspicious database activities as they occur. Each notification provides details of the suspicious activity and recommends how to further investigate and mitigate the threat.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-038', 'eval': 'data.rule.sql_server_retention_days', 'message': 'data.rule.sql_server_retention_days_err', 'remediationDescription': "For Resource type 'microsoft.sql/servers/securityalertpolicies' make sure properties.retentionDays exists and the value is set to greater than 90.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/securityalertpolicies' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_038.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-038
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Azure SQL Server threat detection alerts should be enabled for all threat types\
Test Result: **failed**\
Description : Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F<br>_x005F<br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-039', 'eval': 'data.rule.sql_logical_server_disabled_alerts', 'message': 'data.rule.sql_logical_server_disabled_alerts_err', 'remediationDescription': "For the source type 'microsoft.sql/servers/securityalertpolicies' make sure that properties.disabledAlerts does not exist or is empty.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/securityalertpolicies' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_039.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-039
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-039
Title: Azure SQL Server threat detection alerts should be enabled for all threat types\
Test Result: **passed**\
Description : Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F<br>_x005F<br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.\

#### Test Details
- eval: data.rule.sql_logical_server_disabled_alerts
- id : PR-AZR-ARM-SQL-039

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1699                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.sql/sql-logical-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-SQL-039
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-040
Title: Azure SQL Server threat detection alerts should be enabled for all threat types\
Test Result: **passed**\
Description : Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F<br>_x005F<br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.\

#### Test Details
- eval: data.rule.sql_server_disabled_alerts
- id : PR-AZR-ARM-SQL-040

#### Snapshots
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT806                                                                                                                                          |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                       |
| type          | arm                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-040
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-SQL-040
Title: Azure SQL Server threat detection alerts should be enabled for all threat types\
Test Result: **passed**\
Description : Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F<br>_x005F<br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.\

#### Test Details
- eval: data.rule.sql_server_disabled_alerts
- id : PR-AZR-ARM-SQL-040

#### Snapshots
| Title         | Description                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT894                                                                                                                                |
| structure     | filesystem                                                                                                                                              |
| reference     | master                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                             |
| collection    | armtemplate                                                                                                                                             |
| type          | arm                                                                                                                                                     |
| region        |                                                                                                                                                         |
| resourceTypes | ['microsoft.sql/servers/securityalertpolicies']                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.sql/servers.securityalertpolicies.json'] |

- masterTestId: PR-AZR-ARM-SQL-040
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Azure SQL Server threat detection alerts should be enabled for all threat types\
Test Result: **failed**\
Description : Advanced data security (ADS) provides a set of advanced SQL security capabilities, including vulnerability assessment, threat detection, and data discovery and classification._x005F<br>_x005F<br>This policy identifies Azure SQL servers that have disabled the detection of one or more threat types. To protect your SQL Servers, as a best practice, enable ADS detection for all types of threats.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-040', 'eval': 'data.rule.sql_server_disabled_alerts', 'message': 'data.rule.sql_server_disabled_alerts_err', 'remediationDescription': "For the source type 'microsoft.sql/servers/securityalertpolicies' make sure that properties.disabledAlerts does not exist or is empty.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2018-06-01-preview/servers/securityalertpolicies' target='_blank'>here</a> for more details.", 'remediationFunction': 'PR_AZR_ARM_SQL_040.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-040
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/sql_alert_policy.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'CSA-CCM', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                               |
----------------------------------------------------------------


### Test ID - 
Title: Ensure SQL Server administrator login does not contain 'Admin/Administrator' as name\
Test Result: **failed**\
Description : You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.\

#### Test Details
- eval: [{'id': 'PR-AZR-ARM-SQL-049', 'eval': 'data.rule.sql_logical_server_login', 'message': 'data.rule.sql_logical_server_login_err', 'remediationDescription': 'In Resource of type "Microsoft.Sql/servers/administrators" make sure properties.login exists and the value isn\'t set to \'admin\' or \'administrator\'.<br>Please visit <a href='https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators' target='_blank'>here</a> for more details.', 'remediationFunction': 'PR_AZR_ARM_SQL_049.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-ARM-SQL-049
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

