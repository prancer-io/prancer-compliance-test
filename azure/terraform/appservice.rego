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


#
# PR-AZR-0150-TRF
#

default app_service_https_only = null
#default is false
azure_attribute_absence["app_service_https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.https_only
}

azure_issue["app_service_https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    resource.properties.https_only != true
}

app_service_https_only {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_https_only"]
    not azure_issue["app_service_https_only"]
}

app_service_https_only = false {
    azure_attribute_absence["app_service_https_only"]
}

app_service_https_only = false {
    azure_issue["app_service_https_only"]
}

app_service_https_only_err = "azurerm_app_service property 'https_only' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["app_service_https_only"]
} else = "Azure App Service currently can be accessed via HTTP. Please change it to HTTPS only" {
    azure_issue["app_service_https_only"]
}

app_service_https_only_metadata := {
    "Policy Code": "PR-AZR-0150-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure App Service only be accessed via HTTPS",
    "Policy Description": "This policy will identify the Azure app service which dont have a configuration to allow access only over HTTPS protocol and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-0151-TRF
#

default app_service_latest_tls_configured = null

azure_attribute_absence["app_service_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

#default to 1.2
azure_attribute_absence["app_service_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.min_tls_version
}

azure_issue["app_service_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    site_config.min_tls_version != "1.2"
}

app_service_latest_tls_configured {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_latest_tls_configured"]
    not azure_issue["app_service_latest_tls_configured"]
}

app_service_latest_tls_configured {
    azure_attribute_absence["app_service_latest_tls_configured"]
}

app_service_latest_tls_configured = false {
    azure_issue["app_service_latest_tls_configured"]
}

app_service_latest_tls_configured_err = "azurerm_app_service property 'auth_settings.enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["app_service_latest_tls_configured"]
} else = "Azure App Service currently dont have latest version of tls configured" {
    azure_issue["app_service_latest_tls_configured"]
}

app_service_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-0151-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure App Service has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure app service which dont have latest version of tls configured and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}