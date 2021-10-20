#
# PR-AZR-0010
#

package rule
default rulepass = false

# Azure AKS enable role-based access control (RBAC) not enforced
# If role-based access control (RBAC) enabled test will pass

# https://docs.microsoft.com/en-us/rest/api/aks/managedclusters/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.ContainerService/managedClusters

rulepass {
    lower(input.type) == "microsoft.containerservice/managedclusters"
    input.properties.enableRBAC == true
}

metadata := {
    "Policy Code": "PR-AZR-0010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure AKS enable role-based access control (RBAC) not enforced",
    "Policy Description": "To provide granular filtering of the actions that users can perform, Kubernetes uses role-based access controls (RBAC). This control mechanism lets you assign users, or groups of users, permission to do things like create or modify resources, or view logs from running application workloads. These permissions can be scoped to a single namespace, or granted across the entire AKS cluster.</br> </br> This policy checks your AKS cluster RBAC setting and alerts if disabled.",
    "Resource Type": "microsoft.containerservice/managedclusters",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/aks/managedclusters/get"
}
