#
# PR-GCP-0037
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Master authorized networks disabled
# If Master Authorized Network is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(enableAuthorizeNetwork) == 1
}

# 'masterAuthorizedNetworksConfig.enabled is equals true'
enableAuthorizeNetwork["AuthorizeNetwork"] {
    input.masterAuthorizedNetworksConfig.enabled = true
}

metadata := {
    "Policy Code": "PR-GCP-0037",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Master authorized networks disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Master authorized networks. Enabling Master authorized networks will let the Kubernetes Engine block untrusted non-GCP source IPs from accessing the Kubernetes master through HTTPS.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
