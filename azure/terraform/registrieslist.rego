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
