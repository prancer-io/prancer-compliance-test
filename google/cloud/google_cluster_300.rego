#
# PR-GCP-0030
#

package rule
default rulepass = false

# Kubernetes Engine Cluster Nodes have default Service account for Project access
# If the Kubernetes does not have default service account then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(defaultserviceaccount) == 1
}

# nodePools[*].config.serviceAccount does not contains default

defaultserviceaccount["default_serviceaccount_not_exist"] {
    input.nodePools[_].config.serviceAccount != "default"
}

metadata := {
    "Policy Code": "PR-GCP-0030",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Cluster Nodes have default Service account for Project access",
    "Policy Description": "This policy identifies Kubernetes Engine Cluster Nodes which have default Service account for Project access. By default, Kubernetes Engine nodes are given the Compute Engine default service account. This account has broad access and more permissions than are required to run your Kubernetes Engine cluster. You should create and use a least privileged service account to run your Kubernetes Engine cluster instead of using the Compute Engine default service account. If you are not creating a separate service account for your nodes, you should limit the scopes of the node service account to reduce the possibility of a privilege escalation in an attack.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
