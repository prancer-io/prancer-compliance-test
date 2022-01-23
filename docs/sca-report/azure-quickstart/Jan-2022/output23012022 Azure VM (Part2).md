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

## Azure VM (Part2) Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description               |
|:----------|:--------------------------|
| timestamp | 1642963251579             |
| snapshot  | master-snapshot_gen       |
| container | scenario-azure-quickStart |
| test      | master-test.json          |

## Results

### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT431                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image-md/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image-md/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT437                                                                                                                    |
| structure     | filesystem                                                                                                                                  |
| reference     | master                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                 |
| collection    | armtemplate                                                                                                                                 |
| type          | arm                                                                                                                                         |
| region        |                                                                                                                                             |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-user-disk-md/shared/server-md.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT454                                                                                                                                      |
| structure     | filesystem                                                                                                                                                    |
| reference     | master                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                   |
| type          | arm                                                                                                                                                           |
| region        |                                                                                                                                                               |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-converged-md/shared/server-md.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT456                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                   |
| reference     | master                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                  |
| type          | arm                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-md/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-md/azuredeploy.parameters.json']                      |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT457                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets']                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-multi-sid-apps-md/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-multi-sid-apps-md/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT458                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets']      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-multi-sid-db-md/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-multi-sid-db-md/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT462                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-multi-sid-xscs-md/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-marketplace-image-multi-sid-xscs-md/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                            |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT477                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                            |
| collection    | armtemplate                                                                                                                                            |
| type          | arm                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-user-image-converged-md/shared/server-md.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT493                                                                                                                     |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                  |
| collection    | armtemplate                                                                                                                                  |
| type          | arm                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-3-tier-user-image-md/shared/server-md.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT495                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                   |
| reference     | master                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                  |
| type          | arm                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-file-server-md/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-file-server-md/azuredeploy.parameters.json']                                                |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT500                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-lama-apps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-lama-apps/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT502                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-lama-ascs/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-lama-ascs/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT504                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-lama-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-lama-database/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT509                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults/secrets', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT510                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sccm/sccm-currentbranch/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sccm/sccm-currentbranch/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT511                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sccm/sccm-technicalpreview/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sccm/sccm-technicalpreview/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT512                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/scrapy/scrapy-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/scrapy/scrapy-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT513                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.devtestlab/schedules', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.network/bastionhosts', 'microsoft.network/virtualnetworks/subnets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sharepoint/sharepoint-adfs/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sharepoint/sharepoint-adfs/azuredeploy.parameters.json']                                                                                |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT514                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/shibboleth/shibboleth-cluster-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/shibboleth/shibboleth-cluster-ubuntu/azuredeploy.parameters.json']                                                         |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT515                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/shibboleth/shibboleth-cluster-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/shibboleth/shibboleth-cluster-windows/azuredeploy.parameters.json']                                                       |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT516                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/shibboleth/shibboleth-singlevm-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/shibboleth/shibboleth-singlevm-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT517                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/shibboleth/shibboleth-singlevm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/shibboleth/shibboleth-singlevm-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT521                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets']         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/solace/solace-message-router/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/solace/solace-message-router/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT523                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sonarqube/sonarqube-azuresql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT526                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/spark/spark-2.0-on-suse/spark-2.0-on-suse/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/spark/spark-2.0-on-suse/spark-2.0-on-suse/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT527                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/spark/spark-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/spark/spark-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT529                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/spark/spark-on-ubuntu/jumpbox-resources-enabled.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/spark/spark-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT554                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sqlvm-provisioning-csp/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/sqlvm-provisioning-csp/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT557                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/vm-sql-full-autobackup-autopatching-keyvault/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sql/vm-sql-full-autobackup-autopatching-keyvault/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT558                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/loadbalancers/inboundnatrules', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/swarm/acsengine-swarmmode/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/swarm/acsengine-swarmmode/azuredeploy.parameters.json']                                                                                               |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT559                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.network/loadbalancers/inboundnatrules', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/swarm/docker-swarm-cluster/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/swarm/docker-swarm-cluster/azuredeploy.parameters.json']                                                                                                                                |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT560                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/tableau/tableau-server-single-node/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/tableau/tableau-server-single-node/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT561                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/tomcat/openjdk-tomcat-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/tomcat/openjdk-tomcat-ubuntu-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT562                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/torque/torque-cluster/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/torque/torque-cluster/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT563                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/traefik/docker-portainer-traefik-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/traefik/docker-portainer-traefik-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT564                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/trailbot/stampery-trailbot-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/trailbot/stampery-trailbot-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT568                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/az-400-dev-env/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/az-400-dev-env/azuredeploy.parameters.json']  |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT569                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/tfs-basic-domain/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/tfs-basic-domain/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT570                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/tfs-basic-workgroup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/tfs-basic-workgroup/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT571                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/ubuntu-mate-desktop-vscode/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/ubuntu-mate-desktop-vscode/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT572                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/visual-studio-dev-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/visual-studio-dev-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT573                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/visual-studio-dev-vm-chocolatey/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/visual-studio-dev-vm-chocolatey/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT574                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/visual-studio-dev-vm-o365/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/visual-studio-dev-vm-o365/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT576                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/visual-studio-vstsbuildagent-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/visual-studio-vstsbuildagent-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT577                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets']                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vm-vsts-agent/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vm-vsts-agent/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT578                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vs2019-git-docker-windows2019/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vs2019-git-docker-windows2019/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT579                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-fullbuild-redhat-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-fullbuild-redhat-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT580                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-fullbuild-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-fullbuild-ubuntu-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT581                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-minbuildjava-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-minbuildjava-ubuntu-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT582                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-tomcat-redhat-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-tomcat-redhat-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT583                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-tomcat-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/visualstudio/vsts-tomcat-ubuntu-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT584                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wildfly/wildfly-standalone-centos8/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wildfly/wildfly-standalone-centos8/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT587                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/docker-wordpress-mysql/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/docker-wordpress-mysql/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT589                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.resources/deployments', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/wordpress-mysql-replication/nested/mysql-replication.json']                                                                                                                   |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT594                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/wordpress-single-vm-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/wordpress-single-vm-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT595                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/zulu/Linux-Java-ZuluOpenJDK/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/zulu/Linux-Java-ZuluOpenJDK/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT596                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/zulu/Windows-Java-ZuluOpenJDK/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/zulu/Windows-Java-ZuluOpenJDK/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT597                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/100-marketplace-sample/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/100-marketplace-sample/azuredeploy.parameters.json']                               |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT598                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/2fe-lb80-rdp-1be-nsg-rdp/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/2fe-lb80-rdp-1be-nsg-rdp/azuredeploy.parameters.json']                                                                 |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT599                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/2fe-linux-lb80-ssh-1be-win-nsg-rdp-datadisk-ssd/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/2fe-linux-lb80-ssh-1be-win-nsg-rdp-datadisk-ssd/azuredeploy.parameters.json']                   |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

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
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/bastionhosts', 'microsoft.network/privateendpoints', 'microsoft.network/virtualnetworks', 'microsoft.authorization/roleassignments', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.operationalinsights/workspaces', 'microsoft.containerservice/managedclusters', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.insights/activitylogalerts', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipprefixes', 'microsoft.network/natgateways', 'microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.containerregistry/registries', 'microsoft.network/networksecuritygroups', 'microsoft.operationsmanagement/solutions'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT607                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/alsid-syslog-proxy/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/alsid-syslog-proxy/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT608                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/anti-malware-extension-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/anti-malware-extension-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT612                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-logviewer-goaccess/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-logviewer-goaccess/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT623                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/azmgmt-demo/nestedtemplates/managedVms.json']                                                                                                                                                             |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT666                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/bootstorm-vm-boot-time/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/bootstorm-vm-boot-time/azuredeploy.parameters.json']                                            |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT667                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/centos-2nics-lb-cluster/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/centos-2nics-lb-cluster/azuredeploy.parameters.json']                                                                        |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT673                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/headnode-rdma-disabled.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT674                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/headnode-rdma-enabled.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT675                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/linuxnode.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT680                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/windowsnode-rdma-disabled.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT681                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/windowsnode-rdma-enabled.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/create-hpc-cluster/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT685                                                                                           |
| structure     | filesystem                                                                                                         |
| reference     | master                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                        |
| collection    | armtemplate                                                                                                        |
| type          | arm                                                                                                                |
| region        |                                                                                                                    |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/custom-private-dns/nested/genericvm.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT687                                                                                                                  |
| structure     | filesystem                                                                                                                                |
| reference     | master                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                               |
| collection    | armtemplate                                                                                                                               |
| type          | arm                                                                                                                                       |
| region        |                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ddos-attack-prevention/nested/microsoft.compute/vm.windows.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT694                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.network/virtualnetworkgateways', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/devtest-p2s-iis/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/devtest-p2s-iis/azuredeploy.parameters.json']                                                           |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT695                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/diskraid-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/diskraid-ubuntu-vm/azuredeploy.parameters.json']    |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT696                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/dmz-nsg/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/dmz-nsg/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT697                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/dns-forwarder/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/dns-forwarder/azuredeploy.parameters.json']                                                                                                    |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT703                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/docker-rancher/nodes.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/docker-rancher/azuredeploy.parameters.json']                                                                                                        |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT704                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/docker-rancher/server.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/docker-rancher/azuredeploy.parameters.json']                                                                  |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT705                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/dsc-extension-iis-server-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/dsc-extension-iis-server-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT706                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/dsc-pullserver-to-win-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/dsc-pullserver-to-win-server/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT710                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/eset-vm-extension/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/eset-vm-extension/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT711                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/haproxy-redundant-floatingip-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/haproxy-redundant-floatingip-ubuntu/azuredeploy.parameters.json']                                                |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT713                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/virtualnetworks/virtualnetworkpeerings', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks/subnets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/hub-and-spoke-sandbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/hub-and-spoke-sandbox/azuredeploy.parameters.json']                                                                                                                                                   |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT715                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                   |
| reference     | master                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                  |
| type          | arm                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/iis-2vm-sql-1vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/iis-2vm-sql-1vm/azuredeploy.parameters.json']                                                                                              |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT719                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets', 'microsoft.network/routetables'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ipv6-in-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ipv6-in-vnet/azuredeploy.parameters.json']                                                                                                                          |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT720                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets', 'microsoft.network/routetables'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ipv6-in-vnet-stdlb/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ipv6-in-vnet-stdlb/azuredeploy.parameters.json']                                                                         |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT722                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/kubernetes-on-ubuntu-vmss/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/kubernetes-on-ubuntu-vmss/azuredeploy.parameters.json']   |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT723                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/lamp-app/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/lamp-app/azuredeploy.parameters.json']                                                                        |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT724                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/managed-disk-performance-meter/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/managed-disk-performance-meter/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT725                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/managed-disk-raid-performance-meter/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/managed-disk-raid-performance-meter/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT726                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/mcafee-extension-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/mcafee-extension-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT727                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/memcached-multi-vm-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/memcached-multi-vm-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

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
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT738                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/nested-vms-in-virtual-network/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/nested-vms-in-virtual-network/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT739                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/nfs-ha-cluster-ubuntu/nested/nfs-ha-vm.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/nfs-ha-cluster-ubuntu/nested/nfs-ha.param.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT771                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/oms-extension-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/oms-extension-ubuntu-vm/azuredeploy.parameters.json']                                          |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT773                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/oms-extension-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/oms-extension-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT782                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/openvpn-access-server-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/openvpn-access-server-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT784                                                                                                     |
| structure     | filesystem                                                                                                                   |
| reference     | master                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                  |
| collection    | armtemplate                                                                                                                  |
| type          | arm                                                                                                                          |
| region        |                                                                                                                              |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramvm.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT787                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/bastionhosts', 'microsoft.network/privateendpoints', 'microsoft.network/virtualnetworks', 'microsoft.authorization/roleassignments', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.operationalinsights/workspaces', 'microsoft.containerservice/managedclusters', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/networkinterfaces', 'microsoft.insights/activitylogalerts', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts', 'microsoft.containerregistry/registries', 'microsoft.network/networksecuritygroups', 'microsoft.operationsmanagement/solutions'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT796                                                                                                       |
| structure     | filesystem                                                                                                                     |
| reference     | master                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                    |
| collection    | armtemplate                                                                                                                    |
| type          | arm                                                                                                                            |
| region        |                                                                                                                                |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-alwayson-md-ilb-zones/nestedtemplates/newVM.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT816                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-iops-latency-throughput-demo/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-iops-latency-throughput-demo/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT819                                                                                                   |
| structure     | filesystem                                                                                                                 |
| reference     | master                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                |
| collection    | armtemplate                                                                                                                |
| type          | arm                                                                                                                        |
| region        |                                                                                                                            |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.compute/virtualmachines']                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-spaces-direct/nestedtemplates/newVM.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT823                                                                                                            |
| structure     | filesystem                                                                                                                          |
| reference     | master                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                         |
| collection    | armtemplate                                                                                                                         |
| type          | arm                                                                                                                                 |
| region        |                                                                                                                                     |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.compute/virtualmachines']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-spaces-direct-md-zones/nestedtemplates/newVM.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT832                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/loadbalancers/inboundnatrules']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/subnet-driven-deployment/WinServ.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/subnet-driven-deployment/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT833                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/symantec-extension-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/symantec-extension-windows-vm/azuredeploy.parameters.json']                              |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT835                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/traffic-manager-application-gateway-demo-setup/nested/azuredeploywebserver.json']                                                                                |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT838                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/traffic-manager-demo-setup/nested/azuredeploywebserver.json']                                                               |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT841                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/two-tier-nodejsapp-migration-to-containers-on-azure/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/two-tier-nodejsapp-migration-to-containers-on-azure/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT842                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ubuntu-desktop-gnome/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ubuntu-desktop-gnome/azuredeploy.parameters.json']                                                                                                                         |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT843                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ubuntu-desktop-gnome-rdp/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ubuntu-desktop-gnome-rdp/azuredeploy.parameters.json']   |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT844                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ubuntu-desktop-xfce-rdp/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ubuntu-desktop-xfce-rdp/azuredeploy.parameters.json']     |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT845                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ubuntu-netdisk-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/ubuntu-netdisk-setup/azuredeploy.parameters.json']           |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT846                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-32-data-disks-high-iops/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-32-data-disks-high-iops/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT847                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-cpu-sysbench-meter/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-cpu-sysbench-meter/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT848                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-cse-msi/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-cse-msi/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT849                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-disk-performance-meter/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-disk-performance-meter/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT853                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-win-iis-app-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-win-iis-app-ssl/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT854                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-winrm-keyvault-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-winrm-keyvault-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT855                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets']       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-winrm-lb-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-winrm-lb-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT856                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-winrm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vm-winrm-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT857                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmaccess-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmaccess-on-ubuntu/azuredeploy.parameters.json']         |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT858                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmaccess-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmaccess-on-ubuntu/remove-user.parameters.json']         |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT859                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmaccess-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmaccess-on-ubuntu/single-user.parameters.json']         |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT861                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmss-linux-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmss-linux-jumpbox/azuredeploy.parameters.json']                                                 |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT863                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/vmss-windows-jumpbox/azuredeploy.parameters.json']                                             |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT880                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/website-cluster-centos/nested/lb-resources.json']                                                                                      |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT881                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                             |
| type          | arm                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/website-cluster-centos/nested/mysqlMaster-resources.json']                                      |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT882                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                             |
| type          | arm                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/website-cluster-centos/nested/mysqlSlave-resources.json']                                       |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT883                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                             |
| type          | arm                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/website-cluster-centos/nested/redisMaster-resources.json']                                      |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT884                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                             |
| type          | arm                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/website-cluster-centos/nested/redisSlave-resources.json']                                       |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT886                                                                                                                                                |
| structure     | filesystem                                                                                                                                                              |
| reference     | master                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                             |
| type          | arm                                                                                                                                                                     |
| region        |                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/website-cluster-centos/nested/web-resources.json']                                              |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT903                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.resources/deployments', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/active-directory-new-domain/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/active-directory-new-domain/0.9/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT938                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.appconfiguration/app-configuration/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.appconfiguration/app-configuration/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT947                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.authorization/rbac-builtinrole-multiplevms/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.authorization/rbac-builtinrole-multiplevms/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT949                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.authorization/rbac-builtinrole-virtualmachine/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.authorization/rbac-builtinrole-virtualmachine/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT956                                                                                                                                  |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                               |
| collection    | armtemplate                                                                                                                                               |
| type          | arm                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['microsoft.automation/automationaccounts', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.automation/automation-configuration/nested/provisionServer.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT966                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.cache/redis-high-availability/jumpbox-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.cache/redis-high-availability/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT967                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.cache/redis-high-availability/node-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.cache/redis-high-availability/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT992                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/1-vm-loadbalancer-2-nics/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/1-vm-loadbalancer-2-nics/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT993                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/1vm-2nics-2subnets-1vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/1vm-2nics-2subnets-1vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT994                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets']                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/2-vms-internal-load-balancer/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/2-vms-internal-load-balancer/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT995                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/2-vms-loadbalancer-lbrules/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/2-vms-loadbalancer-lbrules/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT996                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.network/loadbalancers/inboundnatrules', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/2-vms-loadbalancer-natrules/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/2-vms-loadbalancer-natrules/azuredeploy.parameters.json']                                                              |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1001                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/customscript-extension-public-storage-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/customscript-extension-public-storage-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1002                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-linux-vm/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-linux-vm/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1004                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-linux-vm-without-aad/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-linux-vm-without-aad/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1007                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-windows-vm/updateEncryptionSettings-All.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1008                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-windows-vm/updateEncryptionSettings-Data.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1009                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-windows-vm/updateEncryptionSettings-OS.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1010                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-windows-vm-without-aad/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/decrypt-running-windows-vm-without-aad/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1016                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/discover-private-ip-dynamically/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/discover-private-ip-dynamically/azuredeploy.parameters.json']                |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1017                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-azure-storage-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-azure-storage-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1018                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-azure-storage-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-azure-storage-on-ubuntu/push-pull-install.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1019                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-azure-storage-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-azure-storage-on-ubuntu/register-azure-automation.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1020                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-public-storage-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-public-storage-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1021                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-public-storage-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/dsc-linux-public-storage-on-ubuntu/register-azure-automation.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1022                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults']                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1023                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1024                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-linux-vm/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-linux-vm/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1026                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-linux-vm-without-aad/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-linux-vm-without-aad/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1032                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1035                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm-aad-client-cert/updatevm-kek.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm-aad-client-cert/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1036                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm-aad-client-cert/updatevm-nokek.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm-aad-client-cert/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1037                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm-without-aad/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm-without-aad/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1039                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-linux-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-linux-jumpbox/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1040                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.parameters.json']                       |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1042                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.network/loadbalancers/inboundnatrules', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/glassfish-on-suse/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/glassfish-on-suse/azuredeploy.parameters.json']                                                                                                                     |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1044                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/list-storage-keys-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/list-storage-keys-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1045                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.network/loadbalancers/inboundnatrules', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/multi-vm-lb-zones/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/multi-vm-lb-zones/azuredeploy.parameters.json']                                            |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1053                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/ospatching-extension-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/ospatching-extension-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1054                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/premium-storage-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/premium-storage-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1062                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-automatic-static-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-automatic-static-ip/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1064                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/availabilitysets']              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-copy-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-copy-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1066                                                                                                                         |
| structure     | filesystem                                                                                                                                        |
| reference     | master                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                       |
| collection    | armtemplate                                                                                                                                       |
| type          | arm                                                                                                                                               |
| region        |                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-custom-script-output/nestedtemplates/vm.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1068                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-custom-script-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-custom-script-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1069                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-customdata/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-customdata/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1072                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-different-rg-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-different-rg-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1074                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-domain-join/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-domain-join/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1076                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-dynamic-data-disks-selection/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-dynamic-data-disks-selection/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1078                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.compute/disks', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-efficientip-vhd/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-efficientip-vhd/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1079                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/images', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-from-user-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-from-user-image/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1080                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/images', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-generalized-vhd-new-or-existing-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-generalized-vhd-new-or-existing-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1081                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.compute/availabilitysets']               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-linux-dynamic-data-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-linux-dynamic-data-disks/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1082                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-linux-jupyterhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-linux-jupyterhub/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1083                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-linux-serial-output/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-linux-serial-output/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1085                                                                                                                                           |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                         |
| type          | arm                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-msi/nestedtemplates/createVM.json']                              |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1089                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-msi-storage/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-msi-storage/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1090                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-multiple-data-disk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-multiple-data-disk/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1091                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-multiple-ipconfig/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-multiple-ipconfig/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1092                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-multiple-nics-linux/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-multiple-nics-linux/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1093                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-new-or-existing-conditions/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-new-or-existing-conditions/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1095                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.compute/disks', 'microsoft.compute/virtualmachines', 'microsoft.storage/storageaccounts']                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-os-disk-and-data-disk-existing-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-os-disk-and-data-disk-existing-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1096                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-push-certificate-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-push-certificate-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1097                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-secure-password/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-secure-password/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1098                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-freebsd/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-freebsd/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1099                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks/subnets']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-linux/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-linux/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1100                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-linux-with-accelerated-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-linux-with-accelerated-networking/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1101                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups']                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-rhel/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-rhel/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **failed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1102                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-rhel-unmanaged/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vm-simple-rhel-unmanaged/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-VM-001
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/vm.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------

