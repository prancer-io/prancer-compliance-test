package rule
default rulepass = false

# Kubernetes Engine Clusters have Alpha cluster feature enabled
# If Kubernetes Alpha feature is disabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(alphaFeature) == 0
}

# 'enableKubernetesAlpha is true'
alphaFeature["KubernetesAlphaFeature"] {
   input.enableKubernetesAlpha = true
}
