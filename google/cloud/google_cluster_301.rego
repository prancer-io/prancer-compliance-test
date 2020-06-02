package rule
default rulepass = false

# Kubernetes Engine Clusters Basic Authentication is set to Enabled
# If username and password is exist then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(basicauth) == 1
}

# masterAuth.username and masterAuth.password exists'
basicauth["basic_authentication"] {
   input.masterAuth.username != null
   input.masterAuth.password != null
}