package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters

#
# Azure AKS cluster Azure CNI networking not enabled (215)
#

default aks_cni_net = null

azure_attribute_absence["aks_cni_net"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    not resource.properties.networkProfile.networkPlugin
}

azure_issue["aks_cni_net"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    lower(resource.properties.networkProfile.networkPlugin) != "azure"
}

aks_cni_net {
    lower(input.resources[_].type) == "microsoft.containerservice/managedclusters"
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

aks_cni_net_miss_err = "AKS cluster attribute networkProfile.networkPlugin missing in the resource" {
    azure_attribute_absence["aks_cni_net"]
}

#
# Azure AKS cluster HTTP application routing enabled (216)
#

default aks_http_routing = null

azure_attribute_absence["aks_http_routing"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    not resource.properties.addonProfiles.httpApplicationRouting
}

azure_issue["aks_http_routing"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    resource.properties.addonProfiles.httpApplicationRouting.enabled == true
}

aks_http_routing {
    lower(input.resources[_].type) == "microsoft.containerservice/managedclusters"
    not azure_issue["aks_http_routing"]
    not azure_attribute_absence["aks_http_routing"]
}

aks_http_routing = false {
    azure_issue["aks_http_routing"]
}

aks_http_routing = false {
    azure_attribute_absence["aks_http_routing"]
}

aks_http_routing_err = "Azure AKS cluster HTTP application routing enabled" {
    azure_issue["aks_http_routing"]
}

aks_http_routing_miss_err = "AKS cluster attribute addonProfiles.httpApplicationRouting missing in the resource" {
    azure_attribute_absence["aks_http_routing"]
}

#
# Azure AKS cluster monitoring not enabled (217)
#

default aks_monitoring = null

azure_attribute_absence["aks_monitoring"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    not resource.properties.addonProfiles.omsagent.enabled
}

azure_issue["aks_monitoring"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    input.properties.addonProfiles.omsagent.enabled != true
}

aks_monitoring {
    lower(input.resources[_].type) == "microsoft.containerservice/managedclusters"
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

aks_monitoring_miss_err = "AKS cluster attribute addonProfiles.omsagent missing in the resource" {
    azure_attribute_absence["aks_monitoring"]
}

#
# Azure AKS cluster pool profile count contains less than 3 nodes (218)
#

default aks_nodes = null

azure_attribute_absence["aks_nodes"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    not resource.properties.agentPoolProfiles
}

azure_issue["aks_nodes"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    min([ c | c := resource.properties.agentPoolProfiles[_].count]) < 3
}

aks_nodes {
    lower(input.resources[_].type) == "microsoft.containerservice/managedclusters"
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
# Azure AKS enable role-based access control (RBAC) not enforced (219)
#

default aks_rbac = null

azure_attribute_absence["aks_rbac"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    not resource.properties.enableRBAC
}

azure_issue["aks_rbac"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerservice/managedclusters"
    resource.properties.enableRBAC != true
}

aks_rbac {
    lower(input.resources[_].type) == "microsoft.containerservice/managedclusters"
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
