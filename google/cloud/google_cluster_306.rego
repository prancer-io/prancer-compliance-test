package rule
default rulepass = false

# Kubernetes Engine Clusters have Legacy Authorization disabled
# If Legacy Authorization is disabled then Test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(legacyAuthorization) == 0
}

# 'legacyAbac.enabled equals true'
legacyAuthorization["legacy_authorization"] {
   input.legacyAbac.enabled = true
}
