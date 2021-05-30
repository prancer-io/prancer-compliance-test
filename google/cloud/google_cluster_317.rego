#
# PR-GCP-0047
#

package rule
default rulepass = false

# GCP Kubernetes Engine Clusters not configured with private nodes feature
# if cluster set to private cluster then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(private_node_feature) == 1
}

# '$.privateClusterConfig.enablePrivateNodes is true'
private_node_feature["private_node_feature"] {
    input.privateClusterConfig.enablePrivateNodes = true
}

metadata := {
    "Policy Code": "PR-GCP-0047",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters not configured with private nodes feature",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) Clusters which are not configured with the private nodes feature. Private nodes feature makes your master inaccessible from the public internet and nodes do not have public IP addresses, so your workloads run in an environment that is isolated from the internet.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
