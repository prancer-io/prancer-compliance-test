package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry

# PR-AZR-0104-TRF

default adminUserDisabled = null
# default is false
azure_attribute_absence ["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    not resource.properties.admin_enabled
}

azure_issue ["adminUserDisabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_container_registry"
    resource.properties.admin_enabled != false
}

adminUserDisabled {
    azure_attribute_absence["adminUserDisabled"]
    not azure_issue["adminUserDisabled"]
}

adminUserDisabled {
    lower(input.resources[_].type) == "azurerm_container_registry"
    not azure_attribute_absence["adminUserDisabled"]
    not azure_issue["adminUserDisabled"]
}

adminUserDisabled = false {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_err = "Azure Container Registry admin user is currently not disabled" {
    azure_issue["adminUserDisabled"]
}

adminUserDisabled_metadata := {
    "Policy Code": "PR-AZR-0104-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that admin user is disabled for Container Registry",
    "Policy Description": "The value that indicates whether the admin user is enabled. Each container registry includes an admin user account, which is disabled by default. You can enable the admin user and manage its credentials in the Azure portal, or by using the Azure CLI or other Azure tools. All users authenticating with the admin account appear as a single user with push and pull access to the registry. Changing or disabling this account disables registry access for all users who use its credentials.",
    "Resource Type": "azurerm_container_registry",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_registry"
}