#
# PR-GCP-0032
#

package rule
default rulepass = false

# Kubernetes Engine Clusters Client Certificate is set to Enabled
# if clientCertificate and clientKey exist then testcase will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(clientCertificate) == 1
}

# 'masterAuth.clientKey and masterAuth.clientCertificate exist'
clientCertificate["masterAuth"] {
    input.masterAuth["clientKey"] != null
    input.masterAuth["clientCertificate"] != null
}

metadata := {
    "Policy Code": "PR-GCP-0032",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters Client Certificate is set to Disabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have disabled Client Certificate. A client certificate is a base64-encoded public certificate used by clients to authenticate to the cluster endpoint. Enabling Client Certificate will provide more security to authenticate users to the cluster.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
