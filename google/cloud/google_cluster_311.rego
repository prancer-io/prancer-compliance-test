#
# PR-GCP-0041
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Stackdriver Monitoring disabled
# If binary authorization is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
    lower(input.type) == "container.v1.cluster"
   count(binaryAuthorization) == 1
}

# 'binaryAuthorization exist and binaryAuthorization.enabled is true'
binaryAuthorization["binary_authorization"] {
   input.binaryAuthorization
   input.binaryAuthorization.enabled == true
}
