package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters

#
# Azure AKS cluster Azure CNI networking not enabled (215)
#

default aks_cni_net = null

aks_cni_net {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    lower(input.properties.networkProfile.networkPlugin) == "azure"
}

aks_cni_net = false {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    lower(input.properties.networkProfile.networkPlugin) != "azure"
}

aks_cni_net_err = "Azure AKS cluster Azure CNI networking not enabled" {
    aks_cni_net = false
}

#
# Azure AKS cluster HTTP application routing enabled (216)
#

default aks_http_routing = null

aks_http_routing {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    input.properties.addonProfiles.httpApplicationRouting.enabled == false
}

aks_http_routing = false {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    input.properties.addonProfiles.httpApplicationRouting.enabled == true
}

aks_http_routing_err = "Azure AKS cluster HTTP application routing enabled" {
    aks_http_routing == false
}

#
# Azure AKS cluster monitoring not enabled (217)
#

default aks_monitoring = null

aks_monitoring {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    input.properties.addonProfiles.omsagent.enabled == true
}

aks_monitoring = false {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    input.properties.addonProfiles.omsagent.enabled == false
}

aks_monitoring_err = "Azure AKS cluster monitoring not enabled" {
    aks_monitoring == false
}

#
# Azure AKS cluster pool profile count contains less than 3 nodes (218)
#

default aks_nodes = null

aks_nodes {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    min([ c | c := to_number(input.properties.agentPoolProfiles[_].count)]) >= 3
}

aks_nodes = false {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    min([ c | c := to_number(input.properties.agentPoolProfiles[_].count)]) < 3
}

aks_nodes_err = "Azure AKS cluster pool profile count contains less than 3 nodes" {
    aks_nodes == false
}

#
# Azure AKS enable role-based access control (RBAC) not enforced (219)
#

default aks_rbac = false

aks_rbac {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    input.properties.enableRBAC == true
}

aks_rbac = false {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    input.properties.enableRBAC == false
}

aks_rbac_err = "Azure AKS enable role-based access control (RBAC) not enforced" {
    aks_rbac == false
}
