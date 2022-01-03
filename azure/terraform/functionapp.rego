package rule

contains(target_list, element) = true {
  lower(target_list[_]) == element
} else = false { true }

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app
# PR-AZR-TRF-AFA-001

default functionapp_authentication_enabled = null

azure_attribute_absence ["functionapp_authentication_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    not resource.properties.auth_settings
}

azure_attribute_absence ["functionapp_authentication_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    auth_settings := resource.properties.auth_settings[_]
    not auth_settings.enabled
}

azure_issue ["functionapp_authentication_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    auth_settings := resource.properties.auth_settings[_]
    auth_settings.enabled != true
}

functionapp_authentication_enabled {
    lower(input.resources[_].type) == "azurerm_function_app"
    not azure_attribute_absence["functionapp_authentication_enabled"]
    not azure_issue["functionapp_authentication_enabled"]
}

functionapp_authentication_enabled = false {
    azure_issue["functionapp_authentication_enabled"]
}

functionapp_authentication_enabled = false {
    azure_attribute_absence["functionapp_authentication_enabled"]
}

functionapp_authentication_enabled_err = "azurerm_function_app property 'auth_settings.enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["functionapp_authentication_enabled"]
} else = "Azure Function apps Authentication is currently not enabled" {
    azure_issue["functionapp_authentication_enabled"]
}

functionapp_authentication_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-AFA-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Function apps Authentication should be enabled",
    "Policy Description": "Azure Function app provides built-in authentication and authorization capabilities (sometimes referred to as 'Easy Auth'), so you can sign in users and access data by writing minimal or no code in your web app, RESTful API, and mobile back end, and also Azure Functions",
    "Resource Type": "azurerm_function_app",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app
# PR-AZR-TRF-AFA-002

default functionapp_not_accessible_from_all_region = null

azure_attribute_absence ["functionapp_not_accessible_from_all_region"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    not resource.properties.site_config
}

azure_attribute_absence ["functionapp_not_accessible_from_all_region"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    site_config := resource.properties.site_config[_]
    not site_config.cors
}

azure_attribute_absence ["functionapp_not_accessible_from_all_region"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    site_config := resource.properties.site_config[_]
    cors := site_config.cors[_]
    not cors.allowed_origins
}

azure_issue ["functionapp_not_accessible_from_all_region"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    site_config := resource.properties.site_config[_]
    cors := site_config.cors[_]
    contains(cors.allowed_origins, "*")
}

functionapp_not_accessible_from_all_region {
    lower(input.resources[_].type) == "azurerm_function_app"
    not azure_attribute_absence["functionapp_not_accessible_from_all_region"]
    not azure_issue["functionapp_not_accessible_from_all_region"]
}

functionapp_not_accessible_from_all_region = false {
    azure_issue["functionapp_not_accessible_from_all_region"]
}

functionapp_not_accessible_from_all_region = false {
    azure_attribute_absence["functionapp_not_accessible_from_all_region"]
}

functionapp_not_accessible_from_all_region_err = "azurerm_function_app property 'site_config.cors.allowed_origins' need to be exist. Its missing from the resource." {
    azure_attribute_absence["functionapp_not_accessible_from_all_region"]
} else = "Azure Function apps Authentication is currently accessible from all regions" {
    azure_issue["functionapp_not_accessible_from_all_region"]
}

functionapp_not_accessible_from_all_region_metadata := {
    "Policy Code": "PR-AZR-TRF-AFA-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Function apps should not be accessible from all regions",
    "Policy Description": "This policy will identify Azure Function Apps which allows accessibility from all region and give alert if found.",
    "Resource Type": "azurerm_function_app",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app
# PR-AZR-TRF-AFA-003

default functionapp_enabled_latest_http2_protocol = null

azure_attribute_absence ["functionapp_enabled_latest_http2_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    not resource.properties.site_config
}

#Defaults to false
azure_attribute_absence ["functionapp_enabled_latest_http2_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    site_config := resource.properties.site_config[_]
    not site_config.http2_enabled
}

azure_issue ["functionapp_enabled_latest_http2_protocol"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    site_config := resource.properties.site_config[_]
    site_config.http2_enabled != true
}

functionapp_enabled_latest_http2_protocol {
    lower(input.resources[_].type) == "azurerm_function_app"
    not azure_attribute_absence["functionapp_enabled_latest_http2_protocol"]
    not azure_issue["functionapp_enabled_latest_http2_protocol"]
}

functionapp_enabled_latest_http2_protocol = false {
    azure_issue["functionapp_enabled_latest_http2_protocol"]
}

functionapp_enabled_latest_http2_protocol = false {
    azure_attribute_absence["functionapp_enabled_latest_http2_protocol"]
}

functionapp_enabled_latest_http2_protocol_err = "azurerm_function_app property 'site_config.http2_enabled' need to be exist. Its missing from the resource." {
    azure_attribute_absence["functionapp_enabled_latest_http2_protocol"]
} else = "Azure Function apps currently does not have latest 'HTTP Version' enabled" {
    azure_issue["functionapp_enabled_latest_http2_protocol"]
}

functionapp_enabled_latest_http2_protocol_metadata := {
    "Policy Code": "PR-AZR-TRF-AFA-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that 'HTTP Version' is the latest, if used to run the Function app",
    "Policy Description": "Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality. Using the latest HTTP version for web apps to take advantage of security fixes, if any, and/or new functionalities of the newer version. Currently, this policy only applies to Linux web apps.",
    "Resource Type": "azurerm_function_app",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app"
}