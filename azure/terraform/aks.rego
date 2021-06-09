package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_kubernetes_cluster

#
# PR-AZR-0006-TRF
#

default aks_cni_net = null

azure_attribute_absence["aks_cni_net"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.network_policy
}

azure_issue["aks_cni_net"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    lower(resource.properties.network_policy) != "azure"
}

aks_cni_net {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_issue["aks_cni_net"]
    not azure_attribute_absence["aks_cni_net"]
}

aks_cni_net = false {
    azure_issue["aks_cni_net"]
}

aks_cni_net = false {
    azure_attribute_absence["aks_cni_net"]
}

aks_cni_net_err = "Azure AKS cluster Azure CNI networking not enabled" {
    azure_issue["aks_cni_net"]
}

aks_cni_net_miss_err = "AKS cluster attribute network_policy missing in the resource" {
    azure_attribute_absence["aks_cni_net"]
}

aks_cni_net_metadata := {
    "Policy Code": "PR-AZR-0006-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS cluster Azure CNI networking not enabled",
    "Policy Description": "Azure CNI provides the following features over kubenet networking:_x005F_x000D_ _x005F_x000D_ - Every pod in the cluster is assigned an IP address in the virtual network. The pods can directly communicate with other pods in the cluster, and other nodes in the virtual network._x005F_x000D_ - Pods in a subnet that have service endpoints enabled can securely connect to Azure services, such as Azure Storage and SQL DB._x005F_x000D_ - You can create user-defined routes (UDR) to route traffic from pods to a Network Virtual Appliance._x005F_x000D_ - Support for Network Policies securing communication between pods._x005F_x000D_ _x005F_x000D_ This policy checks your AKS cluster for the Azure CNI network plugin and generates an alert if not found.",
    "Compliance": [],
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_kubernetes_cluster"
}

#
# PR-AZR-0007-TRF
#

default aks_http_routing = null

azure_issue["aks_http_routing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    resource.properties.http_application_routing.enabled == true
}

aks_http_routing {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_issue["aks_http_routing"]
}

aks_http_routing = false {
    azure_issue["aks_http_routing"]
}

aks_http_routing_err = "Azure AKS cluster HTTP application routing enabled" {
    azure_issue["aks_http_routing"]
}

aks_http_routing_metadata := {
    "Policy Code": "PR-AZR-0007-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS cluster HTTP application routing enabled",
    "Policy Description": "HTTP application routing configures an Ingress controller in your AKS cluster. As applications are deployed, the solution also creates publicly accessible DNS names for application endpoints. While this makes it easy to access applications that are deployed to your Azure AKS cluster, this add-on is not recommended for production use._x005F_x000D_ _x005F_x000D_ This policy checks your AKS cluster HTTP application routing add-on setting and alerts if enabled.",
    "Compliance": [],
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_kubernetes_cluster"
}

#
# PR-AZR-0008-TRF
#

default aks_monitoring = null

azure_attribute_absence["aks_monitoring"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.oms_agent.enabled
}

azure_issue["aks_monitoring"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    input.properties.oms_agent.enabled != true
}

aks_monitoring {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_issue["aks_monitoring"]
    not azure_attribute_absence["aks_monitoring"]
}

aks_monitoring = false {
    azure_issue["aks_monitoring"]
}

aks_monitoring = false {
    azure_attribute_absence["aks_monitoring"]
}

aks_monitoring_err = "Azure AKS cluster monitoring not enabled" {
    azure_issue["aks_monitoring"]
}

aks_monitoring_miss_err = "AKS cluster attribute oms_agent missing in the resource" {
    azure_attribute_absence["aks_monitoring"]
}

aks_monitoring_metadata := {
    "Policy Code": "PR-AZR-0008-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS cluster monitoring not enabled",
    "Policy Description": "Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications._x005F_x000D_ _x005F_x000D_ This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.",
    "Compliance": [],
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_kubernetes_cluster"
}

#
# PR-AZR-0009-TRF
#

default aks_nodes = null

azure_attribute_absence["aks_nodes"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.default_node_pool.node_count
}

azure_issue["aks_nodes"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    to_number(resource.properties.default_node_pool.node_count) < 3
}

aks_nodes {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_issue["aks_nodes"]
    not azure_attribute_absence["aks_nodes"]
}

aks_nodes = false {
    azure_issue["aks_nodes"]
}

aks_nodes = false {
    azure_attribute_absence["aks_nodes"]
}

aks_nodes_err = "Azure AKS cluster pool profile count contains less than 3 nodes" {
    azure_issue["aks_nodes"]
}

aks_nodes_miss_err = "AKS cluster attribute agentPoolProfiles missing in the resource" {
    azure_attribute_absence["aks_nodes"]
}

aks_nodes_metadata := {
    "Policy Code": "PR-AZR-0009-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS cluster pool profile count contains less than 3 nodes",
    "Policy Description": "Ensure your AKS cluster pool profile count contains 3 or more nodes. This is recommended for a more resilient cluster. (Clusters smaller than 3 may experience downtime during upgrades.)_x005F_x000D_ _x005F_x000D_ This policy checks the size of your cluster pool profiles and alerts if there are fewer than 3 nodes.",
    "Compliance": [],
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_kubernetes_cluster"
}

#
# PR-AZR-0010-TRF
#

default aks_rbac = null

azure_attribute_absence["aks_rbac"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.role_based_access_control.enabled
}

azure_issue["aks_rbac"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    resource.properties.role_based_access_control.enabled != true
}

aks_rbac {
    lower(input.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_issue["aks_rbac"]
    not azure_attribute_absence["aks_rbac"]
}

aks_rbac = false {
    azure_issue["aks_rbac"]
}

aks_rbac = false {
    azure_attribute_absence["aks_rbac"]
}

aks_rbac_err = "Azure AKS enable role-based access control (RBAC) not enforced" {
    azure_issue["aks_rbac"]
}

aks_rbac_miss_err = "AKS cluster attribute enableRBAC missing in the resource" {
    azure_attribute_absence["aks_rbac"]
}

aks_rbac_metadata := {
    "Policy Code": "PR-AZR-0010-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure AKS enable role-based access control (RBAC) not enforced",
    "Policy Description": "To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster._x005F_x000D_ _x005F_x000D_ This policy checks your AKS cluster RBAC setting and alerts if disabled.",
    "Compliance": [],
    "Resource Type": "azurerm_kubernetes_cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_kubernetes_cluster"
}
