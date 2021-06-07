#
# PR-GCP-0051
#

package rule
default rulepass = false

# Kubernetes Engine Clusters without any label information
# If cluster contains some lables then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(resourceLabels) == 1
}

# 'resourceLabels exist and should contains some value'
resourceLabels["resource_labels_exist"] {
    input.resourceLabels
    count(input.resourceLabels) > 0
}

metadata := {
    "Policy Code": "PR-GCP-0051",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters without any label information",
    "Policy Description": "This policy identifies all Kubernetes Engine Clusters which do not have labels. Having a cluster label helps you identify and categorize Kubernetes clusters.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
