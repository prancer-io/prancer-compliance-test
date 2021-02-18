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
   input.properties.enableRBAC == true
}
