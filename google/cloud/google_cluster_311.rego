#
# PR-GCP-0041
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Stackdriver Monitoring disabled
# If binary authorization is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(binaryAuthorization) == 1
}

# 'binaryAuthorization exist and binaryAuthorization.enabled is true'
binaryAuthorization["binary_authorization"] {
    input.binaryAuthorization
    input.binaryAuthorization.enabled == true
}

metadata := {
    "Policy Code": "PR-GCP-0041",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have binary authorization disabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have disabled binary authorization. Binary authorization is a security control that ensures only trusted container images are deployed on GKE clusters. As a best practice, verify images prior to deployment to reduce the risk of running unintended or malicious code in your environment.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
