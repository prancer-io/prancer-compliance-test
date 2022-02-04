package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries

# PR-AZR-ARM-ACR-002

default adminUserDisabled = null

azure_attribute_absence ["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not has_property(resource.properties, "adminUserEnabled")
}

azure_issue ["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    resource.properties.adminUserEnabled != false
}

adminUserDisabled {
    lower(input.resources[_].type) == "microsoft.containerregistry/registries"
    not azure_attribute_absence["adminUserDisabled"]
    not azure_issue["adminUserDisabled"]
}

adminUserDisabled {
    azure_attribute_absence["adminUserDisabled"]
}

adminUserDisabled = false {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_err = "Azure Container Registry admin user is currently not disabled" {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_metadata := {
    "Policy Code": "PR-AZR-ARM-ACR-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that admin user is disabled for Container Registry",
    "Policy Description": "The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.containerregistry/registries"
}



#
# PR-AZR-ARM-ACR-003
#

default acr_classic = null

azure_attribute_absence["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.sku.name
}

source_path[{"acr_classic":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.containerregistry/registries"
    not resource.sku.name
    metadata:= {
        "resource_path": [["resources",i,"sku","name"]]
    }
}

azure_issue["acr_classic"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.sku.name) == "classic"
}

source_path[{"acr_classic":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.containerregistry/registries"
    lower(resource.sku.name) == "classic"
    metadata:= {
        "resource_path": [["resources",i,"sku","name"]]
    }
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
} else = "Azure Container registry property sku.name is missing from the resource" {
    azure_attribute_absence["acr_classic"]
}

acr_classic_metadata := {
    "Policy Code": "PR-AZR-ARM-ACR-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Container Registry should not use the deprecated classic registry",
    "Policy Description": "This policy identifies an Azure Container Registry (ACR) that is using the classic SKU. The initial release of the Azure Container Registry (ACR) service that was offered as a classic SKU is being deprecated and will be unavailable after April 2019. As a best practice, upgrade your existing classic registry to a managed registry.<br><br>For more information, visit https://docs.microsoft.com/en-us/azure/container-registry/container-registry-upgrade",
    "Resource Type": "microsoft.containerregistry/registries",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/containerregistry/registries/list"
}