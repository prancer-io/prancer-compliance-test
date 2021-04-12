#
# PR-GCP-0033
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Alias IP disabled
# If Alias IP is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(useIpAliases) == 1
}

# 'ipAllocationPolicy.useIpAliases equals true'
useIpAliases[input.ipAllocationPolicy["useIpAliases"]] {
    input.ipAllocationPolicy.useIpAliases = true
}
