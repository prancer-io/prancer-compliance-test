package rule

# https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list
# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries
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

acr_classic_metadata := {
    "Policy Code": "PR-AZR-0015-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Container Registry using the deprecated classic registry",
    "Policy Description": "This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry._x005F_x000D_ _x005F_x000D_ For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list"
}





# PR-AZR-0104-ARM

default adminUserEnabled = null

azure_attribute_absence["adminUserEnabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.properties.adminUserEnabled
}

azure_issue["adminUserEnabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    resource.properties.adminUserEnabled != false
}

adminUserEnabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["adminUserEnabled"]
    not azure_issue["adminUserEnabled"]
}

adminUserEnabled = false {
    azure_attribute_absence["adminUserEnabled"]
}

adminUserEnabled = false {
    azure_issue["adminUserEnabled"]
}

adminUserEnabled_miss_err = "Ensure that admin user is disabled for Container Registry" {
    azure_attribute_absence["adminUserEnabled"]
}

adminUserEnabled_err = "Ensure that admin user is disabled for Container Registry" {
    azure_issue["adminUserEnabled"]
}



adminUserEnabled_metadata := {
    "Policy Code": "PR-AZR-0104-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that admin user is disabled for Container Registry",
    "Policy Description": "The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries"
}