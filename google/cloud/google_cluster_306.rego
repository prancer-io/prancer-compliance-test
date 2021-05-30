#
# PR-GCP-0036
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Legacy Authorization disabled
# If Legacy Authorization is disabled then Test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(legacyAuthorization) == 0
}

# 'legacyAbac.enabled equals true'
legacyAuthorization["legacy_authorization"] {
    input.legacyAbac.enabled = true
}

metadata := {
    "Policy Code": "PR-GCP-0036",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Legacy Authorization enabled",
    "Policy Description": "This policy identifies GCP Kubernetes Engine Clusters which have enabled legacy authorizer. The legacy authorizer in Kubernetes Engine grants broad and statically defined permissions to all cluster users. After legacy authorizer setting is disabled, RBAC can limit permissions for authorized users based on need.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
