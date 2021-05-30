#
# PR-GCP-0031
#

package rule
default rulepass = false

# Kubernetes Engine Clusters Basic Authentication is set to Enabled
# If username and password is exist then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(basicauth) == 1
}

# masterAuth.username and masterAuth.password exists'
basicauth["basic_authentication"] {
    input.masterAuth.username != null
    input.masterAuth.password != null
}

metadata := {
    "Policy Code": "PR-GCP-0031",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have enabled Basic authentication. Basic authentication allows a user to authenticate to the cluster with a username and password. Disabling Basic authentication will prevent attacks like brute force. Authenticate using client certificate or IAM.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
