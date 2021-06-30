package rule

# https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list

#
# PR-AZR-0015-TRF
#

default acr_classic = null

azure_attribute_absence["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.sku
}

azure_issue["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    lower(resource.properties.sku) == "classic"
}

acr_classic {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_issue["acr_classic"]
    not azure_attribute_absence["acr_classic"]
}

acr_classic = false {
    azure_issue["acr_classic"]
}

acr_classic = false {
    azure_attribute_absence["acr_classic"]
}

acr_classic_err = "Azure Container Registry using the deprecated classic registry" {
    azure_issue["acr_classic"]
}

acr_classic_miss_err = "Azure Container registry attribute sku missing in the resource" {
    azure_attribute_absence["acr_classic"]
}

acr_classic_metadata := {
    "Policy Code": "PR-AZR-0015-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Container Registry using the deprecated classic registry",
    "Policy Description": "This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry._x005F_x000D_ _x005F_x000D_ For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list"
}
