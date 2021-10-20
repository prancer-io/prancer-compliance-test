#
# PR-AZR-0008
#

package rule
default rulepass = false

# Azure AKS cluster monitoring not enabled
# If  AKS cluster monitoring enabled test will pass

# https://docs.microsoft.com/en-us/rest/api/aks/managedclusters/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.ContainerService/managedClusters

rulepass {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    input.properties.addonProfiles.omsAgent.enabled == true
}

metadata := {
    "Policy Code": "PR-AZR-0008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure AKS cluster monitoring not enabled",
    "Policy Description": "Azure Monitor for containers is a feature designed to monitor the performance of container workloads deployed to either Azure Container Instances or managed Kubernetes clusters hosted on Azure Kubernetes Service (AKS). Monitoring your containers is critical, especially when you're running a production cluster, at scale, with multiple applications.</br> </br> This policy checks your AKS cluster monitoring add-on setting and alerts if no configuration is found, or monitoring is disabled.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/aks/managedclusters/get"
}
