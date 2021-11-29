# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Nov 2021)

## All Services

#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20AKS.md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20KeyVault.md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20PostgreSQL.md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20PostgreSQL.md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20Storage%20Account%20(Part1).md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20Storage%20Account%20(Part2).md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20VM.md

## Terraform Azure VM Services 

Source Repository: https://github.com/hashicorp/terraform-provider-azurerm

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/

## Compliance run Meta Data
| Title     | Description                        |
|:----------|:-----------------------------------|
| timestamp | 1637184834855                      |
| snapshot  | master-snapshot_gen                |
| container | scenario-azure-terraform-hashicorp |
| test      | master-test.json                   |

## Results

### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT25                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_public_ip', 'azurerm_batch_account', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_pool', 'azurerm_network_interface', 'azurerm_image', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_storage_account'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT36                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_data_factory', 'azurerm_public_ip', 'azurerm_mssql_virtual_machine', 'azurerm_role_assignment', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_network', 'azurerm_virtual_machine_extension', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_data_factory_integration_runtime_self_hosted', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/data-factory/shared-self-hosted/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/data-factory/shared-self-hosted/main.tf']                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT72                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_public_ip', 'azurerm_mssql_virtual_machine', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/mssql/mssqlvm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/mssql/mssqlvm/main.tf']                                                                                                                                                         |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_backup_policy_vm', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_recovery_services_vault', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_backup_protected_vm']                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/recovery-services/virtual-machine/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/recovery-services/virtual-machine/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_traffic_manager_profile', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_traffic_manager_endpoint', 'azurerm_resource_group', 'azurerm_virtual_machine_extension']                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT123                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_public_ip', 'azurerm_availability_set', 'azurerm_lb_backend_address_pool', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_lb_nat_rule', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_lb', 'azurerm_lb_rule', 'azurerm_resource_group', 'azurerm_network_interface_nat_rule_association', 'azurerm_virtual_machine', 'azurerm_storage_account']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT126                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_machine', 'azurerm_network_interface']                                                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/bastion-box/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/bastion-box/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/bastion-box/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT127                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_template_deployment', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_storage_account']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT129                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_managed_disk', 'azurerm_virtual_machine_data_disk_attachment', 'azurerm_virtual_machine']                                                                                                                                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/attaching-external-disks/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/attaching-external-disks/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT131                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/basic/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT133                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/from-custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/from-custom-image/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT135                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/from-marketplace-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/from-marketplace-image/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT137                                                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_machine', 'azurerm_network_interface']                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/public-ip/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT138                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_security_group']                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/multiple-network-interfaces/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/multiple-network-interfaces/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT139                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_public_ip', 'azurerm_availability_set', 'azurerm_lb_backend_address_pool', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_lb_nat_rule', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_lb', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_lb_rule', 'azurerm_virtual_machine', 'azurerm_network_security_group']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT141                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/linux/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/linux/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT144                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/windows/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/windows/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT145                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_public_ip', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_security_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT147                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - 
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-VM-001', 'eval': 'data.rule.vm_aset', 'message': 'data.rule.vm_aset_err', 'remediationDescription': "In 'azurerm_virtual_machine' resource, make sure 'availability_set_id' property exist and its value is set from id of 'azurerm_availability_set' resource to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#availability_set_id' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_VM_001.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT149                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'null_resource', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_virtual_machine_extension']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/vm-joined-to-active-directory/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/vm-joined-to-active-directory/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-TRF-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT155                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_subnet_route_table_association', 'azurerm_route_table', 'azurerm_public_ip', 'random_string', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_network', 'azurerm_firewall_application_rule_collection', 'azurerm_firewall_network_rule_collection', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_network_security_group', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_storage_account', 'azurerm_firewall'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_VIRTUAL_MACHINE_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT25                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_public_ip', 'azurerm_batch_account', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_pool', 'azurerm_network_interface', 'azurerm_image', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_storage_account'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_backup_policy_vm', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_recovery_services_vault', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_backup_protected_vm']                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/recovery-services/virtual-machine/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/recovery-services/virtual-machine/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_traffic_manager_profile', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_traffic_manager_endpoint', 'azurerm_resource_group', 'azurerm_virtual_machine_extension']                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **passed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT126                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_machine', 'azurerm_network_interface']                                                                                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/bastion-box/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/bastion-box/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/bastion-box/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT127                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_template_deployment', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_storage_account']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT129                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_managed_disk', 'azurerm_virtual_machine_data_disk_attachment', 'azurerm_virtual_machine']                                                                                                                                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/attaching-external-disks/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/attaching-external-disks/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT131                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/basic/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT133                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/from-custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/from-custom-image/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT135                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/from-marketplace-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/from-marketplace-image/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT137                                                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_machine', 'azurerm_network_interface']                                                                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/managed-disks/public-ip/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT138                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_security_group']                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/multiple-network-interfaces/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/multiple-network-interfaces/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **passed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT139                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_public_ip', 'azurerm_availability_set', 'azurerm_lb_backend_address_pool', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_lb_nat_rule', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_lb', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_lb_rule', 'azurerm_virtual_machine', 'azurerm_network_security_group']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT141                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/linux/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/linux/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT145                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_public_ip', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_security_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-002
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT147                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_virtual_machine']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - 
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-VM-002', 'eval': 'data.rule.vm_linux_disabled_password_auth', 'message': 'data.rule.vm_linux_disabled_password_auth_err', 'remediationDescription': "In 'azurerm_virtual_machine' resource, make sure to set 'disable_password_authentication = true' under 'os_profile_linux_config' block to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#disable_password_authentication' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_VM_002.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_VIRTUAL_MACHINE_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/basic-password/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/basic-password/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **passed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT116                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/basic-ssh/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/basic-ssh/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT117                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/custom-data/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/custom-data/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT118                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/ephemeral-os-disk/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/ephemeral-os-disk/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT119                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_public_ip', 'azurerm_availability_set', 'azurerm_lb_backend_address_pool', 'azurerm_virtual_network', 'azurerm_lb_nat_rule', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_lb', 'azurerm_network_interface_backend_address_pool_association', 'azurerm_resource_group', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/load-balanced/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/load-balanced/main.tf']                                                                                                    |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT120                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_virtual_machine_data_disk_attachment', 'azurerm_resource_group', 'azurerm_managed_disk']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/managed-disk-attachments/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/managed-disk-attachments/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT121                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/provisioner/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/provisioner/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT122                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_public_ip', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/public-ip/main.tf']  |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - 
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-VM-004', 'eval': 'data.rule.vm_type_linux_disabled_password_auth', 'message': 'data.rule.vm_type_linux_disabled_password_auth_err', 'remediationDescription': "In 'azurerm_linux_virtual_machine' resource, make sure to set 'disable_password_authentication = true' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#disable_password_authentication' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_VM_004.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-004
Title: Azure Linux Instance should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux vm password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_password_auth
- id : PR-AZR-TRF-VM-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT158                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_network_interface_application_security_group_association', 'azurerm_resource_group', 'azurerm_network_security_rule', 'azurerm_application_security_group', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/network-interface-app-security-group-association/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/network-interface-app-security-group-association/main.tf']                   |

- masterTestId: TEST_VIRTUAL_MACHINE_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - 
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-VM-005', 'eval': 'data.rule.vm_type_linux_scale_set_disabled_password_auth', 'message': 'data.rule.vm_type_linux_scale_set_disabled_password_auth_err', 'remediationDescription': "In 'azurerm_linux_virtual_machine_scale_set' resource, make sure to set 'disable_password_authentication = true' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine_scale_set#disable_password_authentication' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_VM_005.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT166                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_virtual_machine_scale_set_extension', 'azurerm_resource_group']                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/extensions/custom-script/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/extensions/custom-script/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT167                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_monitor_autoscale_setting', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group']                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/auto-scaling/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/auto-scaling/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT168                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/basic/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT169                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT170                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/custom-data/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/custom-data/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT171                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/data-disks/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/data-disks/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT172                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/ephemeral-os-disk/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/ephemeral-os-disk/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT173                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/extensions/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/extensions/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT174                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group']                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/ipv6/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/ipv6/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT175                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/multiple-nics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/multiple-nics/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT176                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_public_ip_prefix', 'azurerm_resource_group']                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/public-ip-per-instance/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/public-ip-per-instance/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT177                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_lb_nat_pool', 'azurerm_lb', 'azurerm_lb_rule', 'azurerm_resource_group']                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/rolling-upgrade-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/rolling-upgrade-policy/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT178                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_key_vault', 'azurerm_subnet', 'azurerm_resource_group']                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/secrets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/secrets/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT179                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/spot/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/spot/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **passed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT180                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/ssh-keys/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/ssh-keys/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT181                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/system-assigned-identity/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/system-assigned-identity/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT182                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_user_assigned_identity', 'azurerm_resource_group']                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/user-assigned-identity/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/user-assigned-identity/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT183                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_resource_group', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/zones/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/zones/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-005
Title: Azure Linux scale set should not use basic authentication(Use SSH Key Instead)\
Test Result: **failed**\
Description : For security purpose, linux scale set password authentication should be disabled. Use SSH Key Instead.\

#### Test Details
- eval: data.rule.vm_type_linux_scale_set_disabled_password_auth
- id : PR-AZR-TRF-VM-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT187                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_lb_probe', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_lb_nat_pool', 'azurerm_lb', 'azurerm_resource_group']                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/virtual_machine_scale_set/loadbalancer-probe/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/virtual_machine_scale_set/loadbalancer-probe/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/basic-password/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/basic-password/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT116                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/basic-ssh/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/basic-ssh/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT117                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/custom-data/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/custom-data/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT118                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/ephemeral-os-disk/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/ephemeral-os-disk/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT119                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_public_ip', 'azurerm_availability_set', 'azurerm_lb_backend_address_pool', 'azurerm_virtual_network', 'azurerm_lb_nat_rule', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_lb', 'azurerm_network_interface_backend_address_pool_association', 'azurerm_resource_group', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/load-balanced/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/load-balanced/main.tf']                                                                                                    |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT120                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_virtual_machine_data_disk_attachment', 'azurerm_resource_group', 'azurerm_managed_disk']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/managed-disk-attachments/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/managed-disk-attachments/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT121                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group']                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/provisioner/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/provisioner/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT122                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_public_ip', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_resource_group', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/linux/public-ip/main.tf']  |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - 
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-VM-006', 'eval': 'data.rule.vm_type_linux_disabled_extension_operation', 'message': 'data.rule.vm_type_linux_disabled_extension_operation_err', 'remediationDescription': "In 'azurerm_linux_virtual_machine' resource, make sure to set 'allow_extension_operations = false' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#allow_extension_operations' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_VM_006.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-006
Title: Azure Linux Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, linux vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_linux_disabled_extension_operation
- id : PR-AZR-TRF-VM-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT158                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine', 'azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_network_interface_application_security_group_association', 'azurerm_resource_group', 'azurerm_network_security_rule', 'azurerm_application_security_group', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/network-interface-app-security-group-association/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/network-interface-app-security-group-association/main.tf']                   |

- masterTestId: TEST_VIRTUAL_MACHINE_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - 
Title: Azure Windows Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, windows vm extension operation should be disabled.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-VM-007', 'eval': 'data.rule.vm_type_windows_disabled_extension_operation', 'message': 'data.rule.vm_type_windows_disabled_extension_operation_err', 'remediationDescription': "In 'azurerm_windows_virtual_machine' resource, make sure to set 'allow_extension_operations = false' to fix the issue. Please visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/windows_virtual_machine#allow_extension_operations' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_VM_007.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_VIRTUAL_MACHINE_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-007
Title: Azure Windows Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, windows vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_windows_disabled_extension_operation
- id : PR-AZR-TRF-VM-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT150                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_windows_virtual_machine', 'azurerm_resource_group']                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/basic-password/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/basic-password/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-007
Title: Azure Windows Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, windows vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_windows_disabled_extension_operation
- id : PR-AZR-TRF-VM-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_windows_virtual_machine', 'azurerm_resource_group']                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/custom-data/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/custom-data/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-007
Title: Azure Windows Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, windows vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_windows_disabled_extension_operation
- id : PR-AZR-TRF-VM-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT152                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_windows_virtual_machine', 'azurerm_resource_group']                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/ephemeral-os-disk/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/ephemeral-os-disk/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-007
Title: Azure Windows Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, windows vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_windows_disabled_extension_operation
- id : PR-AZR-TRF-VM-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT153                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_windows_virtual_machine', 'azurerm_resource_group', 'azurerm_virtual_machine_extension']                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-joined-to-active-directory/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-joined-to-active-directory/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-007
Title: Azure Windows Instance should not allow extension operation\
Test Result: **failed**\
Description : For security purpose, windows vm extension operation should be disabled.\

#### Test Details
- eval: data.rule.vm_type_windows_disabled_extension_operation
- id : PR-AZR-TRF-VM-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT154                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_windows_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vm.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-003
Title: Azure Virtual Machine should have endpoint protection installed\
Test Result: **failed**\
Description : This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.\

#### Test Details
- eval: data.rule.vm_protection
- id : PR-AZR-TRF-VM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT36                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_data_factory', 'azurerm_public_ip', 'azurerm_mssql_virtual_machine', 'azurerm_role_assignment', 'azurerm_network_interface_security_group_association', 'azurerm_virtual_network', 'azurerm_virtual_machine_extension', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_data_factory_integration_runtime_self_hosted', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_rule', 'azurerm_resource_group', 'azurerm_virtual_machine', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/data-factory/shared-self-hosted/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/data-factory/shared-self-hosted/main.tf']                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_VIRTUAL_MACHINE_EXTENSIONS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vmextensions.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-003
Title: Azure Virtual Machine should have endpoint protection installed\
Test Result: **failed**\
Description : This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.\

#### Test Details
- eval: data.rule.vm_protection
- id : PR-AZR-TRF-VM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_traffic_manager_profile', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_traffic_manager_endpoint', 'azurerm_resource_group', 'azurerm_virtual_machine_extension']                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/traffic-manager/virtual-machine/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_EXTENSIONS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vmextensions.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - 
Title: Azure Virtual Machine should have endpoint protection installed\
Test Result: **failed**\
Description : This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-VM-003', 'eval': 'data.rule.vm_protection', 'message': 'data.rule.vm_protection_err', 'remediationDescription': "In 'azurerm_virtual_machine_extension' resource, set type = 'iaasantimalware' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine_extension#type' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_VM_003.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_VIRTUAL_MACHINE_EXTENSIONS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vmextensions.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-003
Title: Azure Virtual Machine should have endpoint protection installed\
Test Result: **failed**\
Description : This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.\

#### Test Details
- eval: data.rule.vm_protection
- id : PR-AZR-TRF-VM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT149                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'null_resource', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_virtual_machine_extension']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/vm-joined-to-active-directory/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/vm-joined-to-active-directory/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_EXTENSIONS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vmextensions.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-VM-003
Title: Azure Virtual Machine should have endpoint protection installed\
Test Result: **failed**\
Description : This policy identifies Azure Virtual Machines (VMs) that do not have endpoint protection installed. Installing endpoint protection systems (like Antimalware for Azure) provides for real-time protection capability that helps identify and remove viruses, spyware, and other malicious software. As a best practice, install endpoint protection on all VMs and computers to help identify and remove viruses, spyware, and other malicious software.\

#### Test Details
- eval: data.rule.vm_protection
- id : PR-AZR-TRF-VM-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT153                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_public_ip', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_network_interface', 'azurerm_windows_virtual_machine', 'azurerm_resource_group', 'azurerm_virtual_machine_extension']                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-joined-to-active-directory/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-joined-to-active-directory/main.tf'] |

- masterTestId: TEST_VIRTUAL_MACHINE_EXTENSIONS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/vmextensions.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------

