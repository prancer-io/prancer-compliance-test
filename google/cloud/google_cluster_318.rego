#
# PR-GCP-0048
#

package rule

default rulepass = false

# GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image
# if node pool image type is COS

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(image_type_validation) == 1
}

# 'nodeConfig.imageType is equals COS'
image_type_validation["image_type_COS"] {
   startswith(input.nodeConfig.imageType) = "COS"
   nodePool := input.nodePools[_]
   startswith(nodePool.config.imageType) = "COS"
}