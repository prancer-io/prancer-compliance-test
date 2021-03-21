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
