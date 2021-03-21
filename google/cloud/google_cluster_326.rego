#
# PR-GCP-0056
#

package rule
default rulepass = false

# GCP Kubernetes cluster size contains less than 3 nodes with auto upgrade enabled
# If (node counts are 3 or more) and (auto upgrade is true) then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

# $.nodePools[*].management.autoUpgrade is true and $.nodePools[*].initialNodeCount is more than or equals to 3

rulepass = true {
    lower(input.type) == "container.v1.cluster"
   count(initial_node_count) = 1
}

initial_node_count["initial_node_count_and_auto_upgrade"] {
   input.nodePools[_].initialNodeCount >= 3
   input.nodePools[_].management.autoUpgrade = true
}
