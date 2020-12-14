#
# PR-AZR-0007
#

package rule
default rulepass = false

# Azure AKS cluster HTTP application routing enabled
# If AKS cluster HTTP application routing enabled test will pass

# https://docs.microsoft.com/en-us/rest/api/aks/managedclusters/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.ContainerService/managedClusters

rulepass {
   input.properties.addonProfiles.httpApplicationRouting.enabled == false
}
