package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service

#
# PR-AZR-0149-TRF
#

default app_service_auth_enabled = null

azure_attribute_absence["app_service_auth_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.auth_settings
}

azure_attribute_absence["app_service_auth_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    auth_settings := resource.properties.auth_settings[_]
    not auth_settings.enabled
}

azure_issue["app_service_auth_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    auth_settings := resource.properties.auth_settings[_]
    auth_settings.enabled != true
}

app_service_auth_enabled {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_auth_enabled"]
    not azure_issue["app_service_auth_enabled"]
}

app_service_auth_enabled = false {
    azure_attribute_absence["app_service_auth_enabled"]
}

app_service_auth_enabled = false {
    azure_issue["app_service_auth_enabled"]
}

app_service_auth_enabled_err = "azurerm_app_service property 'auth_settings.enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["app_service_auth_enabled"]
} else = "Azure App Service Authentication is currently not enabled" {
    azure_issue["app_service_auth_enabled"]
}

app_service_auth_enabled_metadata := {
    "Policy Code": "PR-AZR-0149-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure App Service Authentication is enabled",
    "Policy Description": "This policy will identify the Azure app service which dont have authentication enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}