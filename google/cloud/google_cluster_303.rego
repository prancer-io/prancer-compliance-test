#
# PR-GCP-0033
#

package rule
default rulepass = false

# Kubernetes Engine Clusters have Alias IP disabled
# If Alias IP is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(useIpAliases) == 1
}

# 'ipAllocationPolicy.useIpAliases equals true'
useIpAliases[input.ipAllocationPolicy["useIpAliases"]] {
    input.ipAllocationPolicy.useIpAliases = true
}

metadata := {
    "Policy Code": "PR-GCP-0033",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters have Alias IP disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Alias IP. Alias IP allows the networking layer to perform anti-spoofing checks to ensure that egress traffic is not sent with arbitrary source IPs. By enabling Alias IPs, Kubernetes Engine clusters can allocate IP addresses from a CIDR block known to Google Cloud Platform. This makes your cluster more scalable and allows your cluster to better interact with other GCP products and entities.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
