#
# PR-GCP-0053
#

package rule
default rulepass = false

# Kubernetes cluster intra-node visibility disabled
# If intra-node visibility is enabled then test will pass

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(introNodeVisibility) == 1
}

# 'networkConfig.enableIntraNodeVisibility is equals to true'
introNodeVisibility["intranode_visibility_enabled"] {
    input.networkConfig.enableIntraNodeVisibility = true
}

metadata := {
    "Policy Code": "PR-GCP-0053",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes cluster intra-node visibility disabled",
    "Policy Description": "With Intranode Visibility, all network traffic in your cluster is seen by the Google Cloud Platform network. This means you can see flow logs for all traffic between Pods, including traffic between Pods on the same node. And you can create firewall rules that apply to all traffic between Pods.<br><br>This policy checks your cluster's intra-node visibility feature and generates an alert if it's disabled.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
