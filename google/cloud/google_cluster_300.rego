#
# PR-GCP-0030
#

package rule
default rulepass = false

# Kubernetes Engine Cluster Nodes have default Service account for Project access
# If the Kubernetes does not have default service account then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(defaultserviceaccount) == 1
}

# nodePools[*].config.serviceAccount does not contains default

defaultserviceaccount["default_serviceaccount_not_exist"] {
   input.nodePools[_].config.serviceAccount != "default"
}
