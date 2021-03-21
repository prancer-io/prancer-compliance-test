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
