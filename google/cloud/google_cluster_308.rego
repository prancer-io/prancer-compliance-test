package rule
default rulepass = false

# GCP Kubernetes Engine Clusters have Network policy disabled
# If 'Network policy for master' and 'Network policy for nodes' are Enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(networkPolicy) == 1
}

# '( networkPolicyConfig.disabled not exist or equals False ) and ( networkpolicy.enabled equals True )'
networkPolicy["NetworkPolicyNotExist"] {
   not input.masterAuth.networkPolicyConfig.disabled
   input.networkPolicy.enabled = true
}
