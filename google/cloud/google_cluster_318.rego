#
# PR-GCP-0048
#

package rule

default rulepass = false

# GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image
# if node pool image type is COS

# API Reference : https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get

# Response will be Cluster Object:
# https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.locations.clusters#Cluster

rulepass = true {
    lower(input.type) == "container.v1.cluster"
    count(image_type_validation) == 1
}

# 'nodeConfig.imageType is equals COS'
image_type_validation["image_type_COS"] {
    startswith(input.nodeConfig.imageType) = "COS"
    nodePool := input.nodePools[_]
    startswith(nodePool.config.imageType) = "COS"
}

metadata := {
    "Policy Code": "PR-GCP-0048",
    "Type": "Cloud",
    "Product": "GCP",
    "Language": "Cloud",
    "Policy Title": "GCP Kubernetes Engine Clusters not using Container-Optimized OS for Node image",
    "Policy Description": "This policy identifies Kubernetes Engine Clusters which do not have a container-optimized operating system for node image. Container-Optimized OS is an operating system image for your Compute Engine VMs that is optimized for running Docker containers. By using Container-Optimized OS for node image, you can bring up your Docker containers on Google Cloud Platform quickly, efficiently, and securely. The Container-Optimized OS node image is based on a recent version of the Linux kernel and is optimized to enhance node security. It is also regularly updated with features, security fixes, and patches. The Container-Optimized OS image provides better support, security, and stability than other images.",
    "Resource Type": "container.v1.cluster",
    "Policy Help URL": "",
    "Resource Help URL": "https://cloud.google.com/kubernetes-engine/docs/reference/rest/v1/projects.zones.clusters/get"
}
