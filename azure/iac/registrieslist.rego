package rule

# https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list

#
# PR-AZR-0015-ARM
#

default acr_classic = null

azure_attribute_absence["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.sku.name
}

azure_issue["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.sku.name) == "classic"
}

acr_classic {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["acr_classic"]
    not azure_issue["acr_classic"]
}

acr_classic = false {
    azure_issue["acr_classic"]
}

acr_classic = false {
    azure_attribute_absence["acr_classic"]
}

acr_classic_err = "Azure Container Registry currently configured with deprecated classic registry. Please change the SKU" {
    azure_issue["acr_classic"]
}

acr_classic_miss_err = "Azure Container registry property sku.name is missing from the resource" {
    azure_attribute_absence["acr_classic"]
}

acr_classic_metadata := {
    "Policy Code": "PR-AZR-0015-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Container Registry should not use the deprecated classic registry",
    "Policy Description": "This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry._x005F_x000D_ _x005F_x000D_ For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list"
}
