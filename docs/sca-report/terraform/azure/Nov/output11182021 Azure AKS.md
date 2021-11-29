# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Nov 2021)

## All Services

#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20AKS.md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20KeyVault.md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20PostgreSQL.md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20PostgreSQL.md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20Storage%20Account%20(Part1).md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20Storage%20Account%20(Part2).md
#### https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20VM.md

## Terraform Azure AKS Services 

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

### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **passed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **failed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **passed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **failed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **failed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **passed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **failed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **passed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **passed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **failed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **failed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **passed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **failed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-001
Title: Azure AKS cluster CNI networking should be enabled\
Test Result: **failed**\
Description : Azure CNI provides the following features over kubenet networking:<br><br>- Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network.<br>- Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB.<br>- You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance.<br>- Support for Network Policies securing communication between pods.<br><br>This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.\

#### Test Details
- eval: data.rule.aks_cni_net
- id : PR-AZR-TRF-AKS-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **failed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **failed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **failed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **failed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **failed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-002
Title: Azure AKS cluster HTTP application routing should be disabled\
Test Result: **passed**\
Description : HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use.<br><br>This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.\

#### Test Details
- eval: data.rule.aks_http_routing
- id : PR-AZR-TRF-AKS-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **passed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-003
Title: Azure AKS cluster monitoring should be enabled\
Test Result: **failed**\
Description : Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.<br><br>This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.\

#### Test Details
- eval: data.rule.aks_monitoring
- id : PR-AZR-TRF-AKS-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-004
Title: Azure AKS cluster pool profile should have minimum 3 or more nodes\
Test Result: **failed**\
Description : Ensure your AKS cluster pool profile contains minimum 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)<br><br>This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.\

#### Test Details
- eval: data.rule.aks_nodes
- id : PR-AZR-TRF-AKS-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_4
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **passed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **passed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-005
Title: Azure AKS role-based access control (RBAC) should be enforced\
Test Result: **failed**\
Description : To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.<br><br>This policy checks your AKS cluster RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_rbac
- id : PR-AZR-TRF-AKS-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_5
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                                    |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-006
Title: Managed Azure AD RBAC for AKS cluster should be enabled\
Test Result: **failed**\
Description : Azure Kubernetes Service (AKS) can be configured to use Azure Active Directory (AD) for user authentication. In this configuration, you sign in to an AKS cluster using an Azure AD authentication token. You can also configure Kubernetes role-based access control (Kubernetes RBAC) to limit access to cluster resources based a user's identity or group membership. This policy checks your AKS cluster Azure Active Directory (AD) RBAC setting and alerts if disabled.\

#### Test Details
- eval: data.rule.aks_aad_rbac_enabled
- id : PR-AZR-TRF-AKS-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_6
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                             |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **passed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-008
Title: AKS cluster shoud have Network Policy configured\
Test Result: **failed**\
Description : Network policy used for building Kubernetes network. - calico or azure.\

#### Test Details
- eval: data.rule.aks_network_policy_configured
- id : PR-AZR-TRF-AKS-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_7
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-007
Title: AKS shoud have an API Server Authorized IP Ranges enabled\
Test Result: **failed**\
Description : Authorized IP Ranges to kubernetes API server\

#### Test Details
- eval: data.rule.aks_api_server_authorized_ip_range_enabled
- id : PR-AZR-TRF-AKS-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_8
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Low

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **failed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/aci_connector_linux/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **failed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/basic-cluster/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **failed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT50                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-azure-cni/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **failed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT51                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_role_assignment', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/egress-with-udr-kubenet/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **failed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT52                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_log_analytics_workspace', 'azurerm_resource_group', 'azurerm_log_analytics_solution']                                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/monitoring-log-analytics/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **failed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT53                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/network-policy-calico/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **failed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT54                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_kubernetes_cluster_node_pool', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/nodes-on-internal-network/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **passed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT55                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **passed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT56                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group', 'azurerm_route_table', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet']                                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/advanced-networking-calico-policy/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **passed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT57                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **passed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT58                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/old/role-based-access-control-azuread/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **passed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT59                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/private-api-server/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **passed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT60                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_kubernetes_cluster']                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/public-ip/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-AKS-009
Title: Kubernetes Dashboard shoud be disabled\
Test Result: **failed**\
Description : Disable the Kubernetes dashboard on Azure Kubernetes Service\

#### Test Details
- eval: data.rule.aks_kub_dashboard_disabled
- id : PR-AZR-TRF-AKS-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT61                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_kubernetes_cluster_node_pool', 'azurerm_kubernetes_cluster', 'azurerm_resource_group']                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/kubernetes/spot-node-pool/main.tf'] |

- masterTestId: TEST_AKS_9
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/aks.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['terraform'] |
----------------------------------------------------------------

