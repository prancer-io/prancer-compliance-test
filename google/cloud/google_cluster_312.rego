#
# PR-GCP-0042
#

package rule
default rulepass = false

# GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled
# if legacy compute engine metadata endpoints disabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

# Steps for disable the legacy metadata: https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata#disable-legacy-apis

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(disable_legacy_endpoints) == 1
}

# 'binaryAuthorization exist and binaryAuthorization.enabled is true'
disable_legacy_endpoints["disable_legacy_endpoints"] {
    input.nodeConfig.metadata["disable-legacy-endpoints"] = "true"
}

metadata := {
    "Policy Code": "PR-GCP-0042",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have legacy compute engine metadata endpoints enabled",
    "Policy Description": "This policy identifies Google Kubernetes Engine (GKE) clusters that have legacy compute engine metadata endpoints enabled. Because GKE uses instance metadata to configure node VMs, some of this metadata is potentially sensitive and should be protected from workloads running on the cluster. Legacy metadata APIs expose the Compute Engine's instance metadata of server endpoints. As a best practice, disable legacy API and use v1 APIs to restrict a potential attacker from retrieving instance metadata.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
