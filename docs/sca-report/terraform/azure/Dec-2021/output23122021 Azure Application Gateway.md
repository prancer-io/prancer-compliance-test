# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Dec 2021)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20AKS.md
#### Application Gateway: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Application%20Gateway.md
#### KeyVault: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20KeyVault.md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20PostgreSQL.md
#### SQL Servers: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20SQL%20Servers.md
#### Storage Account (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Storage%20Account%20(Part1).md
#### Storage Account (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Storage%20Account%20(Part2).md
#### VM: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20VM.md

## Terraform Azure Application Gateway Services 

Source Repository: https://github.com/hashicorp/terraform-provider-azurerm

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/

## Compliance run Meta Data
| Title     | Description                        |
|:----------|:-----------------------------------|
| timestamp | 1640196157576                      |
| snapshot  | master-snapshot_gen                |
| container | scenario-azure-terraform-hashicorp |
| test      | master-test.json                   |

## Results

### Test ID - PR-AZR-TRF-AGW-001
Title: Azure Application Gateway should use TLSv1.2 as minimum version or higher\
Test Result: **failed**\
Description : The Application Gateway supports end-to-end SSL encryption using multiple TLS versions and by default, it supports TLS version 1.0 as the minimum version.<br><br>This policy identifies the Application Gateway instances that are configured to use TLS versions 1.1 or lower as the minimum protocol version. As a best practice set the MinProtocolVersion to TLSv1.2 (if you use custom SSL policy) or use the predefined AppGwSslPolicy20170401S policy.\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-TRF-AGW-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_application_gateway', 'azurerm_private_endpoint', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/main.tf'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AGW-002
Title: Azure Application Gateway should have Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : This policy identifies Azure Application Gateways that do not have Web application firewall (WAF) enabled. As a best practice, enable WAF to manage and protect your web applications behind the Application Gateway from common exploits and vulnerabilities.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-TRF-AGW-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_application_gateway', 'azurerm_private_endpoint', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/main.tf'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego)
- severity: High

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AGW-003
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.https_protocol
- id : PR-AZR-TRF-AGW-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_application_gateway', 'azurerm_private_endpoint', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/main.tf'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego)
- severity: High

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AGW-004
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-TRF-AGW-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_application_gateway', 'azurerm_private_endpoint', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/main.tf'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego)
- severity: High

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AGW-005
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-TRF-AGW-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_application_gateway', 'azurerm_private_endpoint', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/main.tf'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego)
- severity: High

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AGW-006
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-TRF-AGW-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_application_gateway', 'azurerm_private_endpoint', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/main.tf'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego)
- severity: High

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AGW-007
Title: Azure Application Gateway V2 should have the Web application firewall (WAF) enabled with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 for proactive protection against CVE-2021-44228 exploit\
Test Result: **failed**\
Description : It is recommended to enable WAF policy with minimum OWASP ModSecurity Core Rule Set (CRS) version 3.1 on Application Gateway V2 to immediately avail of additional protection from log4j Remote Command Execution. details at https://www.microsoft.com/security/blog/2021/12/11/guidance-for-preventing-detecting-and-hunting-for-cve-2021-44228-log4j-2-exploitation/\

#### Test Details
- eval: data.rule.application_gateways_v2_waf_ruleset_OWASP_active
- id : PR-AZR-TRF-AGW-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_application_gateway', 'azurerm_private_endpoint', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group']                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/application-gateway/main.tf'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/applicationgateways.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------

