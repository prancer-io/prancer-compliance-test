#
# PR-GCP-0038
#

package rule
default rulepass = false

# GCP Kubernetes Engine Clusters have Network policy disabled
# If 'Network policy for master' and 'Network policy for nodes' are Enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(networkPolicy) == 1
}

# '( networkPolicyConfig.disabled not exist or equals False ) and ( networkpolicy.enabled equals True )'
networkPolicy["NetworkPolicyNotExist"] {
    not input.masterAuth.networkPolicyConfig.disabled
    input.networkPolicy.enabled = true
}

metadata := {
    "Policy Code": "PR-GCP-0038",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Network policy disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Network policy. A network policy defines how groups of pods are allowed to communicate with each other and other network endpoints. By enabling network policy in a namespace for a pod, it will reject any connections that are not allowed by the network policy.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
