package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_kubernetes_cluster

#
# PR-AZR-0006-TRF
#

default aks_cni_net = null

azure_attribute_absence["aks_cni_net"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.network_policy
}

azure_issue["aks_cni_net"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    lower(resource.properties.network_policy) != "azure"
}

aks_cni_net {
    lower(input.json.resources[_].type) == "azurerm_kubernetes_cluster"
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

#
# PR-AZR-0007-TRF
#

default aks_http_routing = null

azure_issue["aks_http_routing"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    resource.properties.http_application_routing.enabled == true
}

aks_http_routing {
    lower(input.json.resources[_].type) == "azurerm_kubernetes_cluster"
    not azure_issue["aks_http_routing"]
}

aks_http_routing = false {
    azure_issue["aks_http_routing"]
}

aks_http_routing_err = "Azure AKS cluster HTTP application routing enabled" {
    azure_issue["aks_http_routing"]
}

#
# PR-AZR-0008-TRF
#

default aks_monitoring = null

azure_attribute_absence["aks_monitoring"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.oms_agent.enabled
}

azure_issue["aks_monitoring"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    input.properties.oms_agent.enabled != true
}

aks_monitoring {
    lower(input.json.resources[_].type) == "azurerm_kubernetes_cluster"
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

#
# PR-AZR-0009-TRF
#

default aks_nodes = null

azure_attribute_absence["aks_nodes"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.default_node_pool.node_count
}

azure_issue["aks_nodes"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    to_number(resource.properties.default_node_pool.node_count) < 3
}

aks_nodes {
    lower(input.json.resources[_].type) == "azurerm_kubernetes_cluster"
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

#
# PR-AZR-0010-TRF
#

default aks_rbac = null

azure_attribute_absence["aks_rbac"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    not resource.properties.role_based_access_control.enabled
}

azure_issue["aks_rbac"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_kubernetes_cluster"
    resource.properties.role_based_access_control.enabled != true
}

aks_rbac {
    lower(input.json.resources[_].type) == "azurerm_kubernetes_cluster"
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
