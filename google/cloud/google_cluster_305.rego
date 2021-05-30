#
# PR-GCP-0035
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have HTTP load balancing is enabled
# if HTTP Load balancing is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(httpLoadBalancing) == 0
}

# 'addonsConfig.httpLoadBalancing.disabled equals false'
httpLoadBalancing["httpLoadBalancing"] {
    input.addonsConfig.httpLoadBalancing.disabled = true
}

metadata := {
    "Policy Code": "PR-GCP-0035",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have HTTP load balancing disabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have disabled HTTP load balancing. HTTP/HTTPS load balancing provides global load balancing for HTTP/HTTPS requests destined for your instances. Enabling HTTP/HTTPS load balancers will let the Kubernetes Engine to terminate unauthorized HTTP/HTTPS requests and make better context-aware load balancing decisions.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
