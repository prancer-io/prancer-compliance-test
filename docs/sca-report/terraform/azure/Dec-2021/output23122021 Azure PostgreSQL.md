# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Dec 2021)

#### AKS: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20AKS.md
#### Application Gateway: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Application%20Gateway.md
#### KeyVault: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20KeyVault.md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20PostgreSQL.md
#### Storage Account (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Storage%20Account%20(Part1).md
#### Storage Account (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Storage%20Account%20(Part2).md
#### VM: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20VM.md

## Terraform Azure PostgreSQL Services 

Source Repository: https://github.com/hashicorp/terraform-provider-azurerm

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/

## Compliance run Meta Data
| Title     | Description                        |
|:----------|:-----------------------------------|
| timestamp | 1640197162966                      |
| snapshot  | master-snapshot_gen                |
| container | scenario-azure-terraform-hashicorp |
| test      | master-test.json                   |

## Results

### Test ID - PR-AZR-TRF-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-TRF-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/main.tf'] |

- masterTestId: TEST_postgreSQL_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-028
Title: Ensure Geo-redundant backup is enabled on PostgreSQL database server.\
Test Result: **failed**\
Description : Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.\

#### Test Details
- eval: data.rule.geoRedundantBackup
- id : PR-AZR-TRF-SQL-028

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_private_dns_zone', 'azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/main.tf'] |

- masterTestId: TEST_postgreSQL_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **passed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-TRF-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/main.tf'] |

- masterTestId: TEST_postgreSQL_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-029
Title: Ensure ssl enforcement is enabled on PostgreSQL Database Server.\
Test Result: **passed**\
Description : Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.\

#### Test Details
- eval: data.rule.sslEnforcement
- id : PR-AZR-TRF-SQL-029

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_private_dns_zone', 'azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/main.tf'] |

- masterTestId: TEST_postgreSQL_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-062
Title: PostgreSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)\
Test Result: **passed**\
Description : This policy will identify PostgreSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses\

#### Test Details
- eval: data.rule.pg_ingress_from_any_ip_disabled
- id : PR-AZR-TRF-SQL-062

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/main.tf'] |

- masterTestId: TEST_postgreSQL_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-062
Title: PostgreSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)\
Test Result: **passed**\
Description : This policy will identify PostgreSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses\

#### Test Details
- eval: data.rule.pg_ingress_from_any_ip_disabled
- id : PR-AZR-TRF-SQL-062

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_private_dns_zone', 'azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/main.tf'] |

- masterTestId: TEST_postgreSQL_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-063
Title: PostgreSQL Database Server should have log_checkpoints enabled\
Test Result: **failed**\
Description : A checkpoint is a point in the transaction log sequence at which all data files have been updated to reflect the information in the log. All data files will be flushed to disk. Refer to Section 29.4 for more details about what happens during a checkpoint. this policy will identify Postgresql DB Server which dont have checkpoint log enabled and alert.\

#### Test Details
- eval: data.rule.azurerm_postgresql_configuration_log_checkpoints
- id : PR-AZR-TRF-SQL-063

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/main.tf'] |

- masterTestId: TEST_postgreSQL_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-063
Title: PostgreSQL Database Server should have log_checkpoints enabled\
Test Result: **failed**\
Description : A checkpoint is a point in the transaction log sequence at which all data files have been updated to reflect the information in the log. All data files will be flushed to disk. Refer to Section 29.4 for more details about what happens during a checkpoint. this policy will identify Postgresql DB Server which dont have checkpoint log enabled and alert.\

#### Test Details
- eval: data.rule.azurerm_postgresql_configuration_log_checkpoints
- id : PR-AZR-TRF-SQL-063

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_private_dns_zone', 'azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/main.tf'] |

- masterTestId: TEST_postgreSQL_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-064
Title: PostgreSQL Database Server should have log_connections enabled\
Test Result: **failed**\
Description : Causes each attempted connection to the server to be logged, as well as successful completion of client authentication. Only superusers can change this parameter at session start, and it cannot be changed at all within a session. this policy will identify Postgresql DB Server which dont have log_connections enabled and alert.\

#### Test Details
- eval: data.rule.azurerm_postgresql_configuration_log_connections
- id : PR-AZR-TRF-SQL-064

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/main.tf'] |

- masterTestId: TEST_postgreSQL_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-064
Title: PostgreSQL Database Server should have log_connections enabled\
Test Result: **failed**\
Description : Causes each attempted connection to the server to be logged, as well as successful completion of client authentication. Only superusers can change this parameter at session start, and it cannot be changed at all within a session. this policy will identify Postgresql DB Server which dont have log_connections enabled and alert.\

#### Test Details
- eval: data.rule.azurerm_postgresql_configuration_log_connections
- id : PR-AZR-TRF-SQL-064

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_private_dns_zone', 'azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/main.tf'] |

- masterTestId: TEST_postgreSQL_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-065
Title: PostgreSQL Database Server should have connection_throttling enabled\
Test Result: **failed**\
Description : Enabling connection_throttling allows the PostgreSQL Database to set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources.\

#### Test Details
- eval: data.rule.azurerm_postgresql_configuration_connection_throttling
- id : PR-AZR-TRF-SQL-065

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/main.tf'] |

- masterTestId: TEST_postgreSQL_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-065
Title: PostgreSQL Database Server should have connection_throttling enabled\
Test Result: **failed**\
Description : Enabling connection_throttling allows the PostgreSQL Database to set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources.\

#### Test Details
- eval: data.rule.azurerm_postgresql_configuration_connection_throttling
- id : PR-AZR-TRF-SQL-065

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_private_dns_zone', 'azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/main.tf'] |

- masterTestId: TEST_postgreSQL_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-TRF-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/main.tf'] |

- masterTestId: TEST_postgreSQL_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-066
Title: Ensure PostgreSQL servers don't have public network access enabled\
Test Result: **passed**\
Description : Always use Private Endpoint for PostgreSQL Server\

#### Test Details
- eval: data.rule.postgresql_public_access_disabled
- id : PR-AZR-TRF-SQL-066

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_private_dns_zone', 'azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/main.tf'] |

- masterTestId: TEST_postgreSQL_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-003
Title: PostgreSQL servers should use private link\
Test Result: **passed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your PostgreSQL servers instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.pgsql_server_uses_privatelink
- id : PR-AZR-TRF-SQL-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/postgresql/main.tf'] |

- masterTestId: TEST_postgreSQL_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-SQL-003
Title: PostgreSQL servers should use private link\
Test Result: **passed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your PostgreSQL servers instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.pgsql_server_uses_privatelink
- id : PR-AZR-TRF-SQL-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_private_dns_zone', 'azurerm_virtual_network', 'azurerm_postgresql_server', 'azurerm_private_endpoint', 'azurerm_subnet', 'azurerm_resource_group']                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/private-dns-group/main.tf'] |

- masterTestId: TEST_postgreSQL_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/postgreSQL.rego)
- severity: Medium

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------

