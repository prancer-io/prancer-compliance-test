#
# PR-AZR-0006
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerservice/2020-04-01/managedclusters

rulepass {
    lower(input.type) == "microsoft.containerregistry/registries/webhooks"
    input.properties.networkProfile.networkPlugin == "azure"
}
