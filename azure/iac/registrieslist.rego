package rule

# https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list

#
# Azure Container Registry using the deprecated classic registry (224)
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

acr_classic_miss_err = "Azure Container registry attribute sku.name missing in the resource" {
    azure_attribute_absence["acr_classic"]
}
