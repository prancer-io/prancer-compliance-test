# Automated Vulnerability Scan result and Static Code Analysis for Azure QuickStart Templates (Dec 2021)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20AKS.md
#### Application Gateways (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20Application%20Gateways%20(Part1).md
#### Application Gateways (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20Application%20Gateways%20(Part2).md
#### KV (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part1).md
#### KV (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part2).md
#### KV (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part3).md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20PostgreSQL.md
#### VM (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part1).md
#### VM (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part2).md
#### VM (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part3).md
#### VM (Part4): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part4).md
#### VM (Part5): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part5).md
#### VM (Part6): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part6).md

## Azure VM (Part1) Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description                |
|:----------|:---------------------------|
| timestamp | 1640445816599              |
| snapshot  | master-snapshot_gen        |
| container | scenario-azure-quick-start |
| test      | master-test.json           |

## Results

### Test ID - PR-AZR-ARM-VM-001
Title: Azure Virtual Machine should be assigned to an availability set\
Test Result: **passed**\
Description : To provide application redundancy during planned or unplanned maintenance events, you can group two or more virtual machines (VMs) in an availability set. An availability set ensures that the VMs are distributed across multiple isolated hardware nodes in a cluster so that only a subset of your VMs are impacted should a hardware or software failure occur on Azure.<br><br>This policy identifies Azure VMs that are not deployed in an availability set. As a high availability (HA) best practice, deploy your VMs in an availability set.\

#### Test Details
- eval: data.rule.vm_aset
- id : PR-AZR-ARM-VM-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT4                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/active-directory/active-directory-new-domain/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/active-directory/active-directory-new-domain/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT9                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/active-directory/active-directory-new-domain-ha-2-dc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/active-directory/active-directory-new-domain-ha-2-dc/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT16                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                               |
| type          | arm                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/active-directory/create-ad-forest-with-subdomain/nested/CreateAndPrepnewVM.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT23                                                                                                                                  |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                              |
| collection    | armtemplate                                                                                                                                              |
| type          | arm                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/mongodb-sharded-on-centos/nested/config-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT24                                                                                                                                   |
| structure     | filesystem                                                                                                                                                |
| reference     | master                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                               |
| collection    | armtemplate                                                                                                                                               |
| type          | arm                                                                                                                                                       |
| region        |                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/mongodb-sharded-on-centos/nested/replica-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT25                                                                                                                                             |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                         |
| type          | arm                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/airflow/mongodb-sharded-on-centos/nested/router-resources.json']            |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT28                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/apache/apache2-on-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/apache/apache2-on-ubuntu-vm/azuredeploy.parameters.json']  |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/apache/ubuntu-apache-test-page/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/apache/ubuntu-apache-test-page/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT30                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/apache/vertx-openjdk-apache-mysql-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/apache/vertx-openjdk-apache-mysql-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT31                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/apache/zookeeper-cluster-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/apache/zookeeper-cluster-ubuntu-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT32                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/loadbalancers/inboundnatrules', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/barracuda/barracuda-waf-iis/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/barracuda/barracuda-waf-iis/azuredeploy.parameters.json']                                                                              |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/bitcore/bitcore-centos-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/bitcore/bitcore-centos-vm/azuredeploy.parameters.json']      |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/blockchain/blockchain/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/blockchain/blockchain/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT35                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/blockchain/eris-platform/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/blockchain/eris-platform/azuredeploy.parameters.json']        |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT36                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/blockchain/openchain-blockchain-coinprism/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/blockchain/openchain-blockchain-coinprism/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/connections', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/bosh/bosh-cf-crossregion/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/bosh/bosh-cf-crossregion/azuredeploy.parameters.json']                                                                                     |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT43                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/bosh/bosh-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/bosh/bosh-setup/azuredeploy.parameters.json']                        |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT49                                                                                                                                           |
| structure     | filesystem                                                                                                                                                        |
| reference     | master                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                       |
| type          | arm                                                                                                                                                               |
| region        |                                                                                                                                                                   |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-automate-ha/nested/fe-be-virtualmachines-with-extensions.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT50                                                                                                                                            |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                        |
| type          | arm                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-automate-ha/nested/fe-be-virtualmachines-with-extensions1.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-ha-cluster/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-ha-cluster/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-json-parameters-linux-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-json-parameters-linux-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT65                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/trendp2p-chefnodes.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT66                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/trendp2p-chefserver.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT67                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/trendp2p-dsagents.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT68                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/trendp2p-orchestrator.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT69                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/trendp2p-splunkenterprise.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT70                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/trendp2p-trenddsm.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/datameer-trend-chef-riskanalysis/nested/datameer-hdinsight.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/multi-vm-chef-template-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/multi-vm-chef-template-ubuntu-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT74                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ckan/docker-ckan/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ckan/docker-ckan/azuredeploy.parameters.json']                        |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT78                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/data-node-ds13.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT79                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/data-node-ds14.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT83                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/master-node.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT87                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/vm-10-datadisks.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/vm-5-datadisks.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-on-centos/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT89                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-tableau/nested/data-node-ds13.json']                                                                                                      |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT90                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-tableau/nested/data-node-ds14.json']                                                                                                      |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT92                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-tableau/nested/master-node.json']                                                                                                         |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT96                                                                                                                                  |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                              |
| collection    | armtemplate                                                                                                                                              |
| type          | arm                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudera/cloudera-tableau/nested/tableau-server.json']           |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT98                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudlens/cloudlens-moloch-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudlens/cloudlens-moloch-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT99                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudlens/cloudlens-suricata-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cloudlens/cloudlens-suricata-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT100                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cohesive/cohesive-vns3-free-multiclient-overlay-linux/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cohesive/cohesive-vns3-free-multiclient-overlay-linux/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT101                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/routetables', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/routetables/routes', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cohesive/cohesive-vns3-free-try-now/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/cohesive/cohesive-vns3-free-try-now/azuredeploy.parameters.json']                                                                                                        |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT102                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/concourse/concourse-ci/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/concourse/concourse-ci/azuredeploy.parameters.json']                                               |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT104                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/consul/consul-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/consul/consul-on-ubuntu/azuredeploy.parameters.json']                                                                                   |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT105                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/coscale/coscale-dev-env/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/coscale/coscale-dev-env/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT107                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/datascience/vm-ubuntu-DSVM-GPU-or-CPU/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/datascience/vm-ubuntu-DSVM-GPU-or-CPU/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT108                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/datastax/datastax/nested/nodes.json']                                                                                                                  |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT109                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/datastax/datastax/nested/opscenter.json']                                                                        |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/django-app/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/django-app/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/django/sqldb-django-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/dlworkspace/dlworkspace-deployment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/dlworkspace/dlworkspace-deployment/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/dnx/dnx-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/dnx/dnx-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/docker/docker-simple-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/docker/docker-simple-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT116                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/dokku/dokku-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/dokku/dokku-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT117                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/drone/drone-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/drone/drone-ubuntu-vm/azuredeploy.parameters.json']              |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT119                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch/nestedtemplates/client-nodes-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT120                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                     |
| type          | arm                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces']                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch/nestedtemplates/data-nodes-0disk-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT121                                                                                                                                         |
| structure     | filesystem                                                                                                                                                       |
| reference     | master                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                      |
| type          | arm                                                                                                                                                              |
| region        |                                                                                                                                                                  |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces']                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch/nestedtemplates/data-nodes-16disk-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT122                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                     |
| type          | arm                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces']                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch/nestedtemplates/data-nodes-2disk-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT123                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                     |
| type          | arm                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces']                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch/nestedtemplates/data-nodes-4disk-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT124                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                     |
| type          | arm                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces']                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch/nestedtemplates/data-nodes-8disk-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT126                                                                                                                                       |
| structure     | filesystem                                                                                                                                                     |
| reference     | master                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                    |
| type          | arm                                                                                                                                                            |
| region        |                                                                                                                                                                |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch/nestedtemplates/jumpbox-resources.json']         |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT127                                                                                                                                       |
| structure     | filesystem                                                                                                                                                     |
| reference     | master                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                    |
| type          | arm                                                                                                                                                            |
| region        |                                                                                                                                                                |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch/nestedtemplates/kibana-resources.json']          |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT144                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch-jmeter/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elastic/elasticsearch-jmeter/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT146                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elk/diagnostics-eventhub-elk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elk/diagnostics-eventhub-elk/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT147                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elk/diagnostics-with-elk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elk/diagnostics-with-elk/azuredeploy.parameters.json']      |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT148                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elk/docker-kibana-elasticsearch/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/elk/docker-kibana-elasticsearch/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT150                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ethereum/ethereum-cpp-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ethereum/ethereum-cpp-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ethereum/ethereum-studio-docker-standalone-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ethereum/ethereum-studio-docker-standalone-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT152                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ethereum/go-ethereum-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ethereum/go-ethereum-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT153                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/expanse/go-expanse-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/expanse/go-expanse-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT154                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/github-enterprise/github-enterprise/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/github-enterprise/github-enterprise/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT155                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/gluster/gluster-file-system/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/gluster/gluster-file-system/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT156                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/grafana/Telegraf-InfluxDB-Grafana/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/grafana/Telegraf-InfluxDB-Grafana/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT158                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces']                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/guacamole/guacamole-rdp-vnc-gateway-existing-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/guacamole/guacamole-rdp-vnc-gateway-existing-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT159                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/hazelcase/hazelcast-vm-cluster/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/hazelcase/hazelcast-vm-cluster/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT161                                                                                                                               |
| structure     | filesystem                                                                                                                                             |
| reference     | master                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                            |
| collection    | armtemplate                                                                                                                                            |
| type          | arm                                                                                                                                                    |
| region        |                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ibm-cloud-pak/ibm-cloud-pak-for-data/nested/clusternode.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT176                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                    |
| reference     | master                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                   |
| type          | arm                                                                                                                                                                           |
| region        |                                                                                                                                                                               |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/informatica/informatica-adf-hdinsight-powerbi/nested/virtual-machine-with-plan.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT180                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/intel-lustre/intel-lustre-client-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/intel-lustre/intel-lustre-client-server/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT185                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/intel-lustre/intel-lustre-clients-on-centos/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/intel-lustre/intel-lustre-clients-on-centos/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT187                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/iomad/iomad-cluster-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/iomad/iomad-cluster-ubuntu/azuredeploy.parameters.json']                                  |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT188                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/iomad/iomad-singlevm-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/iomad/iomad-singlevm-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT189                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.storage/storageaccounts']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jboss/jboss-eap-clustered-multivm-rhel/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jboss/jboss-eap-clustered-multivm-rhel/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT191                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.storage/storageaccounts']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jboss/jboss-eap-standalone-rhel/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jboss/jboss-eap-standalone-rhel/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT192                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jboss/jboss-eap-standalone-rhel7/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jboss/jboss-eap-standalone-rhel7/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT193                                                                                                                                       |
| structure     | filesystem                                                                                                                                                     |
| reference     | master                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                    |
| type          | arm                                                                                                                                                            |
| region        |                                                                                                                                                                |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-cicd-container/nested/grafana.json']                   |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT195                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-cicd-vmss/nested/jenkins.json']                                                             |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT197                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-cicd-webapp/nested/jenkins.json']                                                           |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT199                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-cluster-2-linux-1-win/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-cluster-2-linux-1-win/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT201                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                   |
| reference     | master                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                  |
| type          | arm                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                              |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-on-ubuntu/jenkmaster-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT202                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces']                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-on-ubuntu/jenkslave-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/jenkins-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT204                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/multiple-windows-vms-with-common-script/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jenkins/multiple-windows-vms-with-common-script/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT205                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jupyter/vm-linux-Jupyterhub/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/jupyter/vm-linux-Jupyterhub/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT206                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces']                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT208                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-on-ubuntu/jumpbox-resources-enabled.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT211                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/datastore-16disk-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT212                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/datastore-2disk-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT213                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/datastore-8disk-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT215                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/jumpbox-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT217                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/zookeeper-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kafka/kafka-ubuntu-multidisks/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT218                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/loadbalancers/inboundnatrules', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kemp/kemp-loadmaster-ha-pair/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kemp/kemp-loadmaster-ha-pair/azuredeploy.parameters.json']                                                                            |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT219                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kemp/kemp-loadmaster-multinic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/kemp/kemp-loadmaster-multinic/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT223                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lap/lap-mysql-ubuntu/lamplap-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lap/lap-mysql-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT224                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces']                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lap/lap-mysql-ubuntu/lampmysql-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lap/lap-mysql-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT226                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lap/lap-neo4j-ubuntu/nested/lanplap-resources.json']                                                                                                         |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT227                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                        |
| type          | arm                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lap/lap-neo4j-ubuntu/nested/lanpneo4j-resources.json']                     |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT230                                                                                                                                   |
| structure     | filesystem                                                                                                                                                 |
| reference     | master                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                |
| collection    | armtemplate                                                                                                                                                |
| type          | arm                                                                                                                                                        |
| region        |                                                                                                                                                            |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/networksecuritygroups', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mahara/mahara-autoscale-cache/nested/controller.json']             |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT232                                                                                                                           |
| structure     | filesystem                                                                                                                                         |
| reference     | master                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                        |
| collection    | armtemplate                                                                                                                                        |
| type          | arm                                                                                                                                                |
| region        |                                                                                                                                                    |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces']                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mahara/mahara-autoscale-cache/nested/elastic-search.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT235                                                                                                                      |
| structure     | filesystem                                                                                                                                    |
| reference     | master                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                   |
| collection    | armtemplate                                                                                                                                   |
| type          | arm                                                                                                                                           |
| region        |                                                                                                                                               |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces']                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mahara/mahara-autoscale-cache/nested/glustervm.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT246                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/minecraft/minecraft-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/minecraft/minecraft-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT249                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/arbiter-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT252                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces']                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/jumpbox-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT253                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/member-resources-D1.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT254                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/member-resources-D11.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT255                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/member-resources-D12.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT256                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/member-resources-D13.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT257                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/member-resources-D14.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT258                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/member-resources-D2.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT259                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/member-resources-D3.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT260                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/member-resources-D4.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT262                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/arbiter-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT265                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/frontend-resource.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT266                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/networkinterfaces']                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/jumpbox-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT267                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/member-resources-D1.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT268                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/member-resources-D11.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT269                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/member-resources-D12.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT270                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/member-resources-D13.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT271                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/member-resources-D14.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT272                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/member-resources-D2.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT273                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/member-resources-D3.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                           |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT274                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/member-resources-D4.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-nodejs-high-availability/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT276                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-on-centos/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-on-centos/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT277                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT278                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-replica-set-centos/nested/primary-resources.json']                                                       |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT279                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-replica-set-centos/nested/secondary-resources.json']                                                                                          |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                  |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT281                                                                                                                                     |
| structure     | filesystem                                                                                                                                                   |
| reference     | master                                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                  |
| type          | arm                                                                                                                                                          |
| region        |                                                                                                                                                              |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-sharding-centos/nested/config-primary-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT282                                                                                                                                       |
| structure     | filesystem                                                                                                                                                     |
| reference     | master                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                    |
| type          | arm                                                                                                                                                            |
| region        |                                                                                                                                                                |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-sharding-centos/nested/config-secondary-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT284                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                     |
| type          | arm                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-sharding-centos/nested/replica-primary-resources.json']   |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT285                                                                                                                                        |
| structure     | filesystem                                                                                                                                                      |
| reference     | master                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                     |
| type          | arm                                                                                                                                                             |
| region        |                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-sharding-centos/nested/replica-secondary-resources.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT286                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                         |
| type          | arm                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-sharding-centos/nested/router1-resources.json']               |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT287                                                                                                                                            |
| structure     | filesystem                                                                                                                                                          |
| reference     | master                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                         |
| type          | arm                                                                                                                                                                 |
| region        |                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mongo/mongodb-sharding-centos/nested/router2-resources.json']               |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT290                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/moodle/moodle-scalable-cluster-ubuntu/nested/controller.json']                                            |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT292                                                                                                                            |
| structure     | filesystem                                                                                                                                          |
| reference     | master                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                         |
| collection    | armtemplate                                                                                                                                         |
| type          | arm                                                                                                                                                 |
| region        |                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/moodle/moodle-scalable-cluster-ubuntu/nested/elastic.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT295                                                                                                                              |
| structure     | filesystem                                                                                                                                            |
| reference     | master                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                           |
| collection    | armtemplate                                                                                                                                           |
| type          | arm                                                                                                                                                   |
| region        |                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces']                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/moodle/moodle-scalable-cluster-ubuntu/nested/glustervm.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT306                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-ha-pxc/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-ha-pxc/azuredeploy.parameters.json']             |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT309                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-mha-haproxy-ubuntu/nested/haproxy-resources.json']                                                                                               |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT310                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                        |
| type          | arm                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-mha-haproxy-ubuntu/nested/master-resources.json']              |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT312                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                        |
| type          | arm                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-mha-haproxy-ubuntu/nested/slave01-resources.json']             |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT313                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                        |
| type          | arm                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-mha-haproxy-ubuntu/nested/slave02-resources.json']             |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT318                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-replication/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-replication/azuredeploy.parameters.json']   |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT319                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-standalone-server-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/mysql/mysql-standalone-server-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT320                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/nagios/nagios-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/nagios/nagios-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT321                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/neo4j/docker-neo4j/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/neo4j/docker-neo4j/azuredeploy.parameters.json']                    |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT322                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/neo4j/neo4j-ubuntu-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/neo4j/neo4j-ubuntu-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT323                                                                                                              |
| structure     | filesystem                                                                                                                            |
| reference     | master                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                           |
| collection    | armtemplate                                                                                                                           |
| type          | arm                                                                                                                                   |
| region        |                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/netapp/netapp-ontap-sql/nested/jump-vm.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT324                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/netapp/netapp-ontap-sql/nested/netapp-oncommand-cloudmanager.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT328                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/netapp/netapp-ontap-sql/nested/sql-vm.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT330                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/nextflow/nextflow-genomics-cluster-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/nextflow/nextflow-genomics-cluster-ubuntu/azuredeploy.parameters.json']                   |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT331                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/nylas/nylas-email-sync-engine/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/nylas/nylas-email-sync-engine/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT332                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/obs/obs-studio-stream-vm-chocolatey/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/obs/obs-studio-stream-vm-chocolatey/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT333                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/octopus/octopusdeploy3-single-vm-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT334                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces']                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/office/windows-vm-o365/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/office/windows-vm-o365/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT335                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opencanvas/opencanvas-lms/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opencanvas/opencanvas-lms/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT336                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opendx/openedx-devstack-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opendx/openedx-devstack-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT337                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opendx/openedx-fullstack-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opendx/openedx-fullstack-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT338                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/loadbalancers/inboundnatrules', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opendx/openedx-scalable-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opendx/openedx-scalable-ubuntu/azuredeploy.parameters.json']                                                                                                                        |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT339                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opendx/openedx-tutor-lilac-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opendx/openedx-tutor-lilac-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT340                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/openldap/openldap-cluster-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/openldap/openldap-cluster-ubuntu/azuredeploy.parameters.json']                      |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT341                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/openldap/openldap-singlevm-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/openldap/openldap-singlevm-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT342                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/openscholar/openscholar/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/openscholar/openscholar/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT343                                                                                                                                 |
| structure     | filesystem                                                                                                                                               |
| reference     | master                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                              |
| collection    | armtemplate                                                                                                                                              |
| type          | arm                                                                                                                                                      |
| region        |                                                                                                                                                          |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/openshift/openshift-container-platform/nested/clusternode.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT347                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opensis/opensis-cluster-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opensis/opensis-cluster-ubuntu/azuredeploy.parameters.json']                          |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT348                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opensis/opensis-singlevm-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/opensis/opensis-singlevm-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT350                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/parse/docker-parse/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/parse/docker-parse/azuredeploy.parameters.json']                    |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT351                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/perforce/perforce-helix-core-server/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/perforce/perforce-helix-core-server/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT352                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/phabricator/phabricator-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/phabricator/phabricator-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT354                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces']                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/postgre/postgresql-on-ubuntu/database-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/postgre/postgresql-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT355                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/postgre/postgresql-on-ubuntu/jumpbox-resources.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/postgre/postgresql-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT357                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/postgre/postgresql-standalone-server-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/postgre/postgresql-standalone-server-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT359                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/puppet/puppet-agent-linux/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/puppet/puppet-agent-linux/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT360                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/puppet/puppet-agent-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/puppet/puppet-agent-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT361                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/python/python-proxy-on-ubuntu/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/python/python-proxy-on-ubuntu/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT363                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts']                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/qlik/qlik-sense-enterprise/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/qlik/qlik-sense-enterprise/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT364                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/rds/rds-deployment/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/rds/rds-deployment/azuredeploy.parameters.json']                                                                                                                                |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT367                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/rds/rds-deployment-existing-ad/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/rds/rds-deployment-existing-ad/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT368                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.compute/virtualmachines', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/rds/rds-deployment-ha-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/rds/rds-deployment-ha-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT373                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ros/ros-vm-linux/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ros/ros-vm-linux/azuredeploy.parameters.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT376                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ros/ros-vm-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/ros/ros-vm-windows/azuredeploy.parameters.json']       |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT378                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/safekit/safekit-cluster-farm/nestedtemplates/cluster.json']                                                                                                                                                                                                       |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| id            | ARM_TEMPLATE_SNAPSHOT386                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/safekit/safekit-cluster-mirror/nestedtemplates/cluster.json']                                                                                                                                                                  |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT393                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                               |
| type          | arm                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/cs-server-Standard_D13_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT394                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                               |
| type          | arm                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/cs-server-Standard_D14_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT395                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                |
| type          | arm                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/cs-server-Standard_DS11_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT396                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                |
| type          | arm                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/cs-server-Standard_DS13_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT397                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                 |
| reference     | master                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                |
| type          | arm                                                                                                                                                                        |
| region        |                                                                                                                                                                            |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/cs-server-Standard_DS14_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT398                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                   |
| reference     | master                                                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                  |
| type          | arm                                                                                                                                                                          |
| region        |                                                                                                                                                                              |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/cs-server-Standard_DS2_v2_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT399                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                               |
| type          | arm                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines']                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/cs-server-Standard_GS5_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT400                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                               |
| type          | arm                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/db-server-Standard_GS2_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT401                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                               |
| type          | arm                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/db-server-Standard_GS3_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT402                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                               |
| type          | arm                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/db-server-Standard_GS4_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT403                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                |
| reference     | master                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                               |
| type          | arm                                                                                                                                                                       |
| region        |                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/db-server-Standard_GS5_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT425                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/server-md.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT426                                                                                                                                           |
| structure     | filesystem                                                                                                                                                         |
| reference     | master                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                        |
| type          | arm                                                                                                                                                                |
| region        |                                                                                                                                                                    |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/server-Standard_multiNIC_No.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT428                                                                                                                              |
| structure     | filesystem                                                                                                                                            |
| reference     | master                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                           |
| collection    | armtemplate                                                                                                                                           |
| type          | arm                                                                                                                                                   |
| region        |                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/server2-noplan.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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
| Title         | Description                                                                                                                                    |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT429                                                                                                                       |
| structure     | filesystem                                                                                                                                     |
| reference     | master                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                    |
| collection    | armtemplate                                                                                                                                    |
| type          | arm                                                                                                                                            |
| region        |                                                                                                                                                |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sap/sap-2-tier-marketplace-image/shared/server2.json'] |

- masterTestId: TEST_VIRTUAL_MACHINE_1
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

