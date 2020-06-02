package rule
default rulepass = false

# Kubernetes Engine Clusters Client Certificate is set to Enabled
# if clientCertificate and clientKey exist then testcase will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object: 
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {                                      
   count(clientCertificate) == 1
}

# 'masterAuth.clientKey and masterAuth.clientCertificate exist'
clientCertificate["masterAuth"] {
   input.masterAuth["clientKey"] != null
   input.masterAuth["clientCertificate"] != null
}
