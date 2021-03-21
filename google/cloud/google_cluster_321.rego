#
# PR-GCP-0051
#

package rule
default rulepass = false

# Kubernetes Engine Clusters without any label information
# If cluster contains some lables then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
    lower(input.type) == "container.v1.cluster"
   count(resourceLabels) == 1
}

# 'resourceLabels exist and should contains some value'
resourceLabels["resource_labels_exist"] {
   input.resourceLabels
   count(input.resourceLabels) > 0
}
