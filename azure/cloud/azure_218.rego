package rule
default rulepass = false

# Azure AKS cluster pool profile count contains less than 3 nodes
# If  AKS cluster have 3 or more then 3 node pool then test will pass

# https://docs.microsoft.com/en-us/rest/api/aks/managedclusters/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.ContainerService/managedClusters

rulepass = true {                                      
   count(AKS_cluster_node_pool) == 1
}

# properties.agentPoolProfiles.count is 3 or more then 3

AKS_cluster_node_pool["AKS_cluster_node_pool"] {
   input.properties.agentPoolProfiles[_].count >= 3
}
