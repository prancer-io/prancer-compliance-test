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

metadata := {
    "Policy Code": "PR-GCP-0056",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes cluster size contains less than 3 nodes with auto upgrade enabled",
    "Policy Description": "Ensure your Kubernetes cluster size contains 3 or more nodes. (Clusters smaller than 3 may experience downtime during upgrades.)_x005F_x000D_ _x005F_x000D_ This policy checks the size of your cluster pools and alerts if there are fewer than 3 nodes in a pool.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
