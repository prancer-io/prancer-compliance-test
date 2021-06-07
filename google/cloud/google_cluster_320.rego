#
# PR-GCP-0050
#

package rule
default rulepass = false

# GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled
# If kubernetesDashboard is disabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster


# Kubernetes Engine Clusters web UI/Dashboard is set to Disabled
rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(kubernetesdashboard) == 1
}

# 'addonsConfig.kubernetesDashboard does not exist'
kubernetesdashboard["kubernetes_dashboard_is_disabled"] {
    input.addonsConfig.kubernetesDashboard.disabled = true
}

metadata := {
    "Policy Code": "PR-GCP-0050",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which have enabled Kubernetes web UI/Dashboard. Since all the data is being transmitted over HTTP protocol, disabling Kubernetes web UI/Dashboard will protect the data from sniffers on the same network.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
