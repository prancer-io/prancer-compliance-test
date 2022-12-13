package rule

array_contains(target_list, element) = true {
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
    array_contains(cors.allowed_origins, "*")
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


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app
# PR-AZR-TRF-AFA-004

default functionapp_accessed_via_https_only = null

#Defaults to false
azure_attribute_absence ["functionapp_accessed_via_https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    not resource.properties.https_only
}

azure_issue ["functionapp_accessed_via_https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    resource.properties.https_only != true
}

functionapp_accessed_via_https_only {
    lower(input.resources[_].type) == "azurerm_function_app"
    not azure_attribute_absence["functionapp_accessed_via_https_only"]
    not azure_issue["functionapp_accessed_via_https_only"]
}

functionapp_accessed_via_https_only = false {
    azure_issue["functionapp_accessed_via_https_only"]
}

functionapp_accessed_via_https_only = false {
    azure_attribute_absence["functionapp_accessed_via_https_only"]
}

functionapp_accessed_via_https_only_err = "azurerm_function_app property 'https_only' need to be exist. Its missing from the resource." {
    azure_attribute_absence["functionapp_accessed_via_https_only"]
} else = "Azure Function App currently does not redirect HTTP to HTTPS" {
    azure_issue["functionapp_accessed_via_https_only"]
}

functionapp_accessed_via_https_only_metadata := {
    "Policy Code": "PR-AZR-TRF-AFA-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure Function App enforce https connection",
    "Policy Description": "This policy identifies Azure Function App which doesn't redirect HTTP to HTTPS. Azure Function App can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.",
    "Resource Type": "azurerm_function_app",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app
# PR-AZR-TRF-AFA-005

default functionapp_usage_latest_version_of_tls = null

azure_attribute_absence ["functionapp_usage_latest_version_of_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    not resource.properties.site_config
}

# Defaults to 1.2 for new function apps.
azure_attribute_absence ["functionapp_usage_latest_version_of_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    site_config := resource.properties.site_config[_]
    not site_config.min_tls_version
}

azure_issue ["functionapp_usage_latest_version_of_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    site_config := resource.properties.site_config[_]
    to_number(site_config.min_tls_version) != 1.2 # though tf resource has string value but currently prancer compliance engine is converting string to float (not sure why). thats why we need to compare as number.
}

functionapp_usage_latest_version_of_tls {
    lower(input.resources[_].type) == "azurerm_function_app"
    not azure_attribute_absence["functionapp_usage_latest_version_of_tls"]
    not azure_issue["functionapp_usage_latest_version_of_tls"]
}

functionapp_usage_latest_version_of_tls = false {
    azure_issue["functionapp_usage_latest_version_of_tls"]
}

functionapp_usage_latest_version_of_tls {
    lower(input.resources[_].type) == "azurerm_function_app"
    azure_attribute_absence["functionapp_usage_latest_version_of_tls"]
    not azure_issue["functionapp_usage_latest_version_of_tls"]
}

functionapp_usage_latest_version_of_tls_err = "Azure Function App currently not configured with latest version TLS" {
    azure_issue["functionapp_usage_latest_version_of_tls"]
}

functionapp_usage_latest_version_of_tls_metadata := {
    "Policy Code": "PR-AZR-TRF-AFA-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Function App should use the latest version of TLS encryption",
    "Policy Description": "This policy identifies Azure Function App which are not set with latest version of TLS encryption. Azure currently allows the Function App to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for Function App secure connections.",
    "Resource Type": "azurerm_function_app",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app
# PR-AZR-TRF-AFA-006

default functionapp_client_certificate_enabled = null

azure_attribute_absence ["functionapp_client_certificate_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    not resource.properties.client_cert_mode
}

azure_issue ["functionapp_client_certificate_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    lower(resource.properties.client_cert_mode) != "required"
}

functionapp_client_certificate_enabled {
    lower(input.resources[_].type) == "azurerm_function_app"
    not azure_attribute_absence["functionapp_client_certificate_enabled"]
    not azure_issue["functionapp_client_certificate_enabled"]
}

functionapp_client_certificate_enabled = false {
    azure_issue["functionapp_client_certificate_enabled"]
}

functionapp_client_certificate_enabled = false {
    azure_attribute_absence["functionapp_client_certificate_enabled"]
}

functionapp_client_certificate_enabled_err = "azurerm_function_app property 'client_cert_mode' need to be exist. Its missing from the resource." {
    azure_attribute_absence["functionapp_client_certificate_enabled"]
} else = "Azure Function App does not have incoming client certificates enabled" {
    azure_issue["functionapp_client_certificate_enabled"]
}

functionapp_client_certificate_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-AFA-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Function App should have incoming client certificates enabled",
    "Policy Description": "This policy will identify the Azure app service which has missing configuration about requiring client certificates for incoming requests and give alert",
    "Resource Type": "azurerm_function_app",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app
# PR-AZR-TRF-AFA-007

default functionapp_managed_identity_provider_enabled = null

azure_attribute_absence ["functionapp_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    not resource.properties.identity
}

azure_attribute_absence ["functionapp_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    identity := resource.properties.identity[_]
    not identity.type
}

azure_issue ["functionapp_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    identity := resource.properties.identity[_]
    not contains(lower(identity.type), "systemassigned")
}

azure_issue ["functionapp_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_function_app"
    identity := resource.properties.identity[_]
    not contains(lower(identity.type), "userassigned")
}

functionapp_managed_identity_provider_enabled {
    lower(input.resources[_].type) == "azurerm_function_app"
    not azure_attribute_absence["functionapp_managed_identity_provider_enabled"]
    not azure_issue["functionapp_managed_identity_provider_enabled"]
}

functionapp_managed_identity_provider_enabled = false {
    azure_issue["functionapp_managed_identity_provider_enabled"]
}

functionapp_managed_identity_provider_enabled = false {
    azure_attribute_absence["functionapp_managed_identity_provider_enabled"]
}

functionapp_managed_identity_provider_enabled_err = "azurerm_function_app property 'identity.type' need to be exist. Its missing from the resource." {
    azure_attribute_absence["functionapp_managed_identity_provider_enabled"]
} else = "Azure Function App currently dont have any identity provider enabled" {
    azure_issue["functionapp_managed_identity_provider_enabled"]
}

functionapp_managed_identity_provider_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-AFA-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Function App Managed Identity provider should be enabled",
    "Policy Description": "This policy identifies Azure Function App which doesn't have a Managed Service Identity. Managed service identity in Function App makes the app more secure by eliminating secrets from the app, such as credentials in the connection strings. When registering with Azure Active Directory in the app service, the app will connect to other Azure services securely without the need of username and passwords.",
    "Resource Type": "azurerm_function_app",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app"
}