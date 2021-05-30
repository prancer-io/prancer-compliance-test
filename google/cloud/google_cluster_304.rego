#
# PR-GCP-0034
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Alpha cluster feature enabled
# If Kubernetes Alpha feature is disabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(alphaFeature) == 0
}

# 'enableKubernetesAlpha is true'
alphaFeature["KubernetesAlphaFeature"] {
    input.enableKubernetesAlpha = true
}

metadata := {
    "Policy Code": "PR-GCP-0034",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Alpha cluster feature enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled alpha cluster. It is recommended to not use alpha clusters or alpha features for production workloads. Alpha clusters expire after 30 days and do not receive security updates. This cluster will not be covered by the Kubernetes Engine SLA.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
