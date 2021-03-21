#
# PR-GCP-0037
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Master authorized networks disabled
# If Master Authorized Network is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
   count(enableAuthorizeNetwork) == 1
}

# 'masterAuthorizedNetworksConfig.enabled is equals true'
enableAuthorizeNetwork["AuthorizeNetwork"] {
   input.masterAuthorizedNetworksConfig.enabled = true
}
