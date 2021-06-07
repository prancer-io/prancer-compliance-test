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

metadata := {
    "Policy Code": "PR-AZR-0015",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Container Registry using the deprecated classic registry",
    "Policy Description": "This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry._x005F_x000D_ _x005F_x000D_ For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list"
}

# ['sku.name != "classic"'] is not exist

classicregistry["classic_registry_is_not_exist"] {
    lower(input.type) == "microsoft.containerregistry/registries"
    lower(input.sku.name) != "classic"
}
