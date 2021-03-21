#
# PR-GCP-0042
#

package rule
default rulepass = false

# GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled
# if legacy compute engine metadata endpoints disabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

# Steps for disable the legacy metadata: https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#disable-legacy-apis

rulepass = true {                                      
    lower(input.type) == "container.v1.cluster"
   count(disable_legacy_endpoints) == 1
}

# 'binaryAuthorization exist and binaryAuthorization.enabled is true'
disable_legacy_endpoints["disable_legacy_endpoints"] {
   input.nodeConfig.metadata["disable-legacy-endpoints"] = "true"   
}
