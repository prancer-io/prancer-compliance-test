package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app
# PR-AZR-TRF-AFA-001

default functionapp_authentication_enabled = null

azure_attribute_absence ["functionapp_authentication_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    not resource.properties.auth_settings
}

azure_issue ["functionapp_authentication_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    auth_settings := resource.properties.auth_settings[_]
    not auth_settings.enabled
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