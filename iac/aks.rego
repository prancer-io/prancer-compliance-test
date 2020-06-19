package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/managedclusters

#
# Azure AKS cluster Azure CNI networking not enabled (215)
#

default aks_cni_net = null

aks_cni_net {
    input.type == "Microsoft.ContainerService/managedClusters"
    input.properties.networkProfile.networkPlugin == "azure"
}

aks_cni_net = false {
    input.type == "Microsoft.ContainerService/managedClusters"
    input.properties.networkProfile.networkPlugin != "azure"
}

aks_cni_net_err = "Azure AKS cluster Azure CNI networking not enabled" {
    aks_cni_net = false
}

#
# Azure AKS cluster HTTP application routing enabled (216)
#

default aks_http_routing = null

aks_http_routing {
    input.type == "Microsoft.ContainerService/managedClusters"
    input.properties.addonProfiles.httpApplicationRouting.enabled == false
}

aks_http_routing = false {
    input.type == "Microsoft.ContainerService/managedClusters"
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
    input.type == "Microsoft.ContainerService/managedClusters"
    input.properties.addonProfiles.omsagent.enabled == true
}

aks_monitoring = false {
    input.type == "Microsoft.ContainerService/managedClusters"
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
    input.type == "Microsoft.ContainerService/managedClusters"
    min([ c | c := to_number(input.properties.agentPoolProfiles[_].count)]) >= 3
}

aks_nodes = false {
    input.type == "Microsoft.ContainerService/managedClusters"
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
    input.type == "Microsoft.ContainerService/managedClusters"
    input.properties.enableRBAC == true
}

aks_rbac = false {
    input.type == "Microsoft.ContainerService/managedClusters"
    input.properties.enableRBAC == false
}

aks_rbac_err = "Azure AKS enable role-based access control (RBAC) not enforced" {
    aks_rbac == false
}
