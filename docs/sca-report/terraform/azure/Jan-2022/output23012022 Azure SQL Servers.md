# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Jan 2022)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20AKS.md
#### Application Gateway: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20Application%20Gateway.md
#### KeyVault: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20KeyVault.md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20PostgreSQL.md
#### SQL Servers: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20SQL%20Servers.md
#### Storage Account (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20Storage%20Account%20(Part1).md
#### Storage Account (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20Storage%20Account%20(Part2).md
#### VM: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20VM.md

## Terraform Azure SQL Servers Services

Source Repository: https://github.com/hashicorp/terraform-provider-azurerm

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform

## Compliance run Meta Data
| Title     | Description                        |
|:----------|:-----------------------------------|
| timestamp | 1642942001275                      |
| snapshot  | master-snapshot_gen                |
| container | scenario-azure-terraform-hashicorp |
| test      | master-test.json                   |

## Results

### Test ID - PR-AZR-TRF-SQL-046
Title: Ensure SQL server's TDE protector is encrypted with Customer-managed key\
Test Result: **failed**\
Description : Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.\

#### Test Details
- eval: data.rule.serverKeyType
- id : PR-AZR-TRF-SQL-046

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_resource_group', 'azurerm_mssql_database', 'azurerm_sql_failover_group']                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-046
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers_encryption.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-046
Title: Ensure SQL server's TDE protector is encrypted with Customer-managed key\
Test Result: **failed**\
Description : Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.\

#### Test Details
- eval: data.rule.serverKeyType
- id : PR-AZR-TRF-SQL-046

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_eventhub', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_eventhub_namespace', 'azurerm_resource_group', 'azurerm_eventhub_namespace_authorization_rule', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_mssql_database'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/main.tf']                                                                         |

- masterTestId: PR-AZR-TRF-SQL-046
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers_encryption.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-046
Title: Ensure SQL server's TDE protector is encrypted with Customer-managed key\
Test Result: **failed**\
Description : Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.\

#### Test Details
- eval: data.rule.serverKeyType
- id : PR-AZR-TRF-SQL-046

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_resource_group', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_log_analytics_workspace', 'azurerm_mssql_database']   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-046
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers_encryption.rego)
- severity: Medium

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database Server and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-TRF-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_resource_group', 'azurerm_mssql_database', 'azurerm_sql_failover_group']                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-047
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database Server and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-TRF-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_eventhub', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_eventhub_namespace', 'azurerm_resource_group', 'azurerm_eventhub_namespace_authorization_rule', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_mssql_database'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/main.tf']                                                                         |

- masterTestId: PR-AZR-TRF-SQL-047
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-047
Title: Ensure SQL servers don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure SQL Database Server and SQL Managed Instance\

#### Test Details
- eval: data.rule.sql_public_access_disabled
- id : PR-AZR-TRF-SQL-047

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_resource_group', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_log_analytics_workspace', 'azurerm_mssql_database']   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-047
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description                                                     |
|:-----------|:----------------------------------------------------------------|
| cloud      | git                                                             |
| compliance | ['CIS', 'CSA-CCM', 'HIPAA', 'ISO 27001', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-048
Title: Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name\
Test Result: **failed**\
Description : You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.\

#### Test Details
- eval: data.rule.sql_server_login
- id : PR-AZR-TRF-SQL-048

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_resource_group', 'azurerm_mssql_database', 'azurerm_sql_failover_group']                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-048
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['terraform']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-048
Title: Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name\
Test Result: **failed**\
Description : You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.\

#### Test Details
- eval: data.rule.sql_server_login
- id : PR-AZR-TRF-SQL-048

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_eventhub', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_eventhub_namespace', 'azurerm_resource_group', 'azurerm_eventhub_namespace_authorization_rule', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_mssql_database'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/main.tf']                                                                         |

- masterTestId: PR-AZR-TRF-SQL-048
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['terraform']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-048
Title: Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name\
Test Result: **failed**\
Description : You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.\

#### Test Details
- eval: data.rule.sql_server_login
- id : PR-AZR-TRF-SQL-048

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_resource_group', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_log_analytics_workspace', 'azurerm_mssql_database']   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-048
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: Medium

tags
| Title      | Description                                                            |
|:-----------|:-----------------------------------------------------------------------|
| cloud      | git                                                                    |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practice'] |
| service    | ['terraform']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-068
Title: MSSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)\
Test Result: **failed**\
Description : This policy will identify MSSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses\

#### Test Details
- eval: data.rule.mssql_ingress_from_any_ip_disabled
- id : PR-AZR-TRF-SQL-068

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_resource_group', 'azurerm_mssql_database', 'azurerm_sql_failover_group']                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-068
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-068
Title: MSSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)\
Test Result: **failed**\
Description : This policy will identify MSSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses\

#### Test Details
- eval: data.rule.mssql_ingress_from_any_ip_disabled
- id : PR-AZR-TRF-SQL-068

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_eventhub', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_eventhub_namespace', 'azurerm_resource_group', 'azurerm_eventhub_namespace_authorization_rule', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_mssql_database'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/main.tf']                                                                         |

- masterTestId: PR-AZR-TRF-SQL-068
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-068
Title: MSSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)\
Test Result: **failed**\
Description : This policy will identify MSSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses\

#### Test Details
- eval: data.rule.mssql_ingress_from_any_ip_disabled
- id : PR-AZR-TRF-SQL-068

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_resource_group', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_log_analytics_workspace', 'azurerm_mssql_database']   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-068
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-069
Title: Ensure Azure MSSQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure MSSQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.mssql_server_latest_tls_configured
- id : PR-AZR-TRF-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_resource_group', 'azurerm_mssql_database', 'azurerm_sql_failover_group']                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/failover_group/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-069
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-069
Title: Ensure Azure MSSQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure MSSQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.mssql_server_latest_tls_configured
- id : PR-AZR-TRF-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_eventhub', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_eventhub_namespace', 'azurerm_resource_group', 'azurerm_eventhub_namespace_authorization_rule', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_mssql_database'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_eventhub/main.tf']                                                                         |

- masterTestId: PR-AZR-TRF-SQL-069
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-069
Title: Ensure Azure MSSQL Server has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure MSSQL Server which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.mssql_server_latest_tls_configured
- id : PR-AZR-TRF-SQL-069

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_mssql_server', 'azurerm_mssql_database_extended_auditing_policy', 'azurerm_resource_group', 'azurerm_mssql_server_extended_auditing_policy', 'azurerm_monitor_diagnostic_setting', 'azurerm_log_analytics_workspace', 'azurerm_mssql_database']   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/sql-azure/sql_auditing_log_analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-SQL-069
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/sql_servers.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------

