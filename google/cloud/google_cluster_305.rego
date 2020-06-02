package rule
default rulepass = false

# Kubernetes Engine Clusters have HTTP load balancing is enabled
# if HTTP Load balancing is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(httpLoadBalancing) == 0
}

# 'addonsConfig.httpLoadBalancing.disabled equals false'
httpLoadBalancing["httpLoadBalancing"] {
   input.addonsConfig.httpLoadBalancing.disabled = true
}