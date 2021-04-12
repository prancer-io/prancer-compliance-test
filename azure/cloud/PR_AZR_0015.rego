#
# PR-AZR-0015
#

package rule
default rulepass = false

# Azure Container Registry using the deprecated classic registry
# If container registry is not classis version test case will pass

# https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.ContainerRegistry/registries/hardikregistry

rulepass {
    count(classicregistry) == 1
}

# ['sku.name != "classic"'] is not exist

classicregistry["classic_registry_is_not_exist"] {
    lower(input.type) == "microsoft.containerregistry/registries"
    lower(input.sku.name) != "classic"
}
