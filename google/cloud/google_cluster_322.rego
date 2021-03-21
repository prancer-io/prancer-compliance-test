#
# PR-GCP-0052
#

package rule
default rulepass = false

# GCP Kubernetes cluster Application-layer Secrets not encrypted
# If GCP Kubernetes cluster Application-layer Secrets is encrypted then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
    lower(input.type) == "container.v1.cluster"
   count(database_encryption) == 1
}

# 'databaseEncryption.state is equals to ENCRYPTED'
database_encryption["application_layer_encrypted"] {
   input.databaseEncryption.state = "ENCRYPTED"
   input.databaseEncryption.keyName != null
}
