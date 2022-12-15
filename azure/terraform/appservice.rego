package rule

#
# PR-AZR-TRF-WEB-001
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
    "Policy Code": "PR-AZR-TRF-WEB-001",
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
# PR-AZR-TRF-WEB-002
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
    to_number(site_config.min_tls_version) != 1.2 # though tf resource has string value but currently prancer compliance engine is converting string to float (not sure why). thats why we need to compare as number.
}

app_service_latest_tls_configured {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_latest_tls_configured"]
    not azure_issue["app_service_latest_tls_configured"]
}

app_service_latest_tls_configured {
    lower(input.resources[_].type) == "azurerm_app_service"
    azure_attribute_absence["app_service_latest_tls_configured"]
    not azure_issue["app_service_latest_tls_configured"]
}

app_service_latest_tls_configured = false {
    azure_issue["app_service_latest_tls_configured"]
}

app_service_latest_tls_configured_err = "Azure App Service currently dont have latest version of tls configured" {
    azure_issue["app_service_latest_tls_configured"]
}

app_service_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure App Service has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure app service which dont have latest version of tls configured and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}

#
# PR-AZR-TRF-WEB-003
#

default app_service_client_cert_enabled = null
#default is false
azure_attribute_absence["app_service_client_cert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.client_cert_enabled
}

azure_issue["app_service_client_cert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    resource.properties.client_cert_enabled != true
}

app_service_client_cert_enabled {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_client_cert_enabled"]
    not azure_issue["app_service_client_cert_enabled"]
}

app_service_client_cert_enabled = false {
    azure_attribute_absence["app_service_client_cert_enabled"]
}

app_service_client_cert_enabled = false {
    azure_issue["app_service_client_cert_enabled"]
}

app_service_client_cert_enabled_err = "azurerm_app_service property 'client_cert_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["app_service_client_cert_enabled"]
} else = "Azure App Service currently can be accessed via HTTP. Please change it to HTTPS only" {
    azure_issue["app_service_client_cert_enabled"]
}

app_service_client_cert_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure App Service require client certificates for incoming requests",
    "Policy Description": "This policy will identify the Azure app service which has missing configuration about requiring client certificates for incoming requests and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-004
#

default app_service_uses_http_two = null

azure_attribute_absence["app_service_uses_http_two"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

#default to false
azure_attribute_absence["app_service_uses_http_two"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.http2_enabled
}

azure_issue["app_service_uses_http_two"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    site_config.http2_enabled != true
}

app_service_uses_http_two {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_uses_http_two"]
    not azure_issue["app_service_uses_http_two"]
}

app_service_uses_http_two = false {
    azure_attribute_absence["app_service_uses_http_two"]
}

app_service_uses_http_two = false {
    azure_issue["app_service_uses_http_two"]
}

app_service_uses_http_two_err = "azurerm_app_service property 'site_config.http2_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["app_service_uses_http_two"]
} else = "Azure App Service currently dont have latest http2 protocol enabled" {
    azure_issue["app_service_uses_http_two"]
}

app_service_uses_http_two_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure App Service has latest http2 protocol enabled",
    "Policy Description": "This policy will identify the Azure app service which dont have latest http2 protocol enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service

#
# PR-AZR-TRF-WEB-005
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
    "Policy Code": "PR-AZR-TRF-WEB-005",
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
# PR-AZR-TRF-WEB-006
#

default app_service_cors_not_allowing_all = null

contains(array, element) = true {
  lower(array[_]) == element
} else = false { true }

azure_attribute_absence["app_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

azure_attribute_absence["app_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.cors
}

azure_attribute_absence["app_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    cors := site_config.cors[_]
    not cors.allowed_origins 
}

azure_issue["app_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    cors := site_config.cors[_]
    contains(cors.allowed_origins, "*") 
}

app_service_cors_not_allowing_all {
    lower(input.resources[_].type) == "azurerm_app_service"
    azure_attribute_absence["app_service_cors_not_allowing_all"]
    not azure_issue["app_service_cors_not_allowing_all"]
}

app_service_cors_not_allowing_all {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_cors_not_allowing_all"]
    not azure_issue["app_service_cors_not_allowing_all"]
}

app_service_cors_not_allowing_all = false {
    azure_issue["app_service_cors_not_allowing_all"]
}

app_service_cors_not_allowing_all_err = "CORS configuration is currently allowing every resources to access Azure App Service" {
    azure_issue["app_service_cors_not_allowing_all"]
}

app_service_cors_not_allowing_all_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure CORS configuration is not allowing every resources to access Azure App Service",
    "Policy Description": "This policy will identify CORS configuration which are allowing every resoruces to access Azure app service and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-007
#

default app_service_http_logging_enabled = null

azure_attribute_absence["app_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.logs
}

azure_attribute_absence["app_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    logs := resource.properties.logs[_]
    not logs.http_logs
}

app_service_http_logging_enabled = false {
    azure_attribute_absence["app_service_http_logging_enabled"]
} else = true {
    lower(input.resources[_].type) == "azurerm_app_service"
	#true
}

app_service_http_logging_enabled_err = "azurerm_app_service property 'logs.http_logs' need to be exist. Its missing from the resource." {
    azure_attribute_absence["app_service_http_logging_enabled"]
}

app_service_http_logging_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service http logging should be enabled",
    "Policy Description": "This policy will identify the Azure app service which dont have http logging enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-008
#

default app_service_detaild_error_message_enabled = null

azure_attribute_absence["app_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.logs
}

#default to false
azure_attribute_absence["app_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    logs := resource.properties.logs[_]
    not logs.detailed_error_messages_enabled
}

azure_issue["app_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    logs := resource.properties.logs[_]
    logs.detailed_error_messages_enabled != true
}

app_service_detaild_error_message_enabled {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_detaild_error_message_enabled"]
    not azure_issue["app_service_detaild_error_message_enabled"]
}

app_service_detaild_error_message_enabled = false {
    azure_attribute_absence["app_service_detaild_error_message_enabled"]
}

app_service_detaild_error_message_enabled = false {
    azure_issue["app_service_detaild_error_message_enabled"]
}

app_service_detaild_error_message_enabled_err = "azurerm_app_service property 'logs.detailed_error_messages_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["app_service_detaild_error_message_enabled"]
} else = "Azure App Service detaild error message currently not enabled" {
    azure_issue["app_service_detaild_error_message_enabled"]
}

app_service_detaild_error_message_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service detaild error message should be enabled",
    "Policy Description": "This policy will identify the Azure app service which dont have detaild error message enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-009
#

default app_service_failed_request_tracing_enabled = null

azure_attribute_absence["app_service_failed_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.logs
}

#default to false
azure_attribute_absence["app_service_failed_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    logs := resource.properties.logs[_]
    not logs.failed_request_tracing_enabled
}

azure_issue["app_service_failed_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    logs := resource.properties.logs[_]
    logs.failed_request_tracing_enabled != true
}

app_service_failed_request_tracing_enabled {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_failed_request_tracing_enabled"]
    not azure_issue["app_service_failed_request_tracing_enabled"]
}

app_service_failed_request_tracing_enabled = false {
    azure_attribute_absence["app_service_failed_request_tracing_enabled"]
}

app_service_failed_request_tracing_enabled = false {
    azure_issue["app_service_failed_request_tracing_enabled"]
}

app_service_failed_request_tracing_enabled_err = "azurerm_app_service property 'logs.app_service_failed_request_tracing_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["app_service_failed_request_tracing_enabled"]
} else = "Azure App Service Failed request tracing currently not enabled" {
    azure_issue["app_service_failed_request_tracing_enabled"]
}

app_service_failed_request_tracing_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service Failed request tracing should be enabled",
    "Policy Description": "This policy will identify the Azure app service which dont have Failed request tracing enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-010
#

default app_service_managed_identity_provider_enabled = null

azure_attribute_absence["app_service_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.identity
}

azure_attribute_absence["app_service_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    identity := resource.properties.identity[_]
    not identity.type
}

app_service_managed_identity_provider_enabled = false {
    azure_attribute_absence["app_service_managed_identity_provider_enabled"]
} else = true {
    lower(input.resources[_].type) == "azurerm_app_service"
}

app_service_managed_identity_provider_enabled_err = "azurerm_app_service property 'identity.type' need to be exist. Its missing from the resource." {
    azure_attribute_absence["app_service_managed_identity_provider_enabled"]
}

app_service_managed_identity_provider_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service Managed Identity provider should be enabled",
    "Policy Description": "This policy will identify the Azure app service which dont have Managed Identity provider enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-011
#

default app_service_remote_debugging_disabled = null

azure_attribute_absence["app_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

#default to false
azure_attribute_absence["app_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.remote_debugging_enabled
}

azure_issue["app_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    site_config.remote_debugging_enabled == true
}

app_service_remote_debugging_disabled {
    lower(input.resources[_].type) == "azurerm_app_service"
    azure_attribute_absence["app_service_remote_debugging_disabled"]
    not azure_issue["app_service_remote_debugging_disabled"]
}

app_service_remote_debugging_disabled {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_remote_debugging_disabled"]
    not azure_issue["app_service_remote_debugging_disabled"]
}

app_service_remote_debugging_disabled = false {
    azure_issue["app_service_remote_debugging_disabled"]
}

app_service_remote_debugging_disabled_err = "Azure App Service remote debugging currently not disabled" {
    azure_issue["app_service_remote_debugging_disabled"]
}

app_service_remote_debugging_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service remote debugging should be disabled",
    "Policy Description": "This policy will identify the Azure app service which have remote debugging enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-012
#

default app_service_ftp_deployment_disabled = null

azure_attribute_absence["app_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

azure_attribute_absence["app_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.ftps_state
}

azure_issue["app_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    lower(site_config.ftps_state) != "disabled"
    lower(site_config.ftps_state) != "ftpsonly"
}

app_service_ftp_deployment_disabled = false {
    azure_attribute_absence["app_service_ftp_deployment_disabled"]
}

app_service_ftp_deployment_disabled {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_ftp_deployment_disabled"]
    not azure_issue["app_service_ftp_deployment_disabled"]
}

app_service_ftp_deployment_disabled = false {
    azure_issue["app_service_ftp_deployment_disabled"]
}

app_service_ftp_deployment_disabled_err = "azurerm_app_service property 'site_config.ftps_state' need to be exist. Its missing from the resource." {
    azure_attribute_absence["app_service_ftp_deployment_disabled"]
} else = "Azure App Service FTP deployment is currently not disabled" {
    azure_issue["app_service_ftp_deployment_disabled"]
}

app_service_ftp_deployment_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-012",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service FTP deployments should be disabled",
    "Policy Description": "This policy will identify the Azure app service which have FTP deployment enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-013
#

default app_service_dot_net_framework_latest = null

latest_dotnet_framework_version := "v6.0"
default_dotnet_framework_version := "v4.0"

azure_attribute_absence["app_service_dot_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

#Defaults to v4.0
azure_attribute_absence["app_service_dot_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.dotnet_framework_version
}

azure_issue["app_service_dot_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    lower(site_config.dotnet_framework_version) != latest_dotnet_framework_version
    lower(site_config.dotnet_framework_version) != default_dotnet_framework_version
}

# we need to make it pass if property is missing, as azurerm_app_service may not need dot net framework
app_service_dot_net_framework_latest {
    lower(input.resources[_].type) == "azurerm_app_service"
    azure_attribute_absence["app_service_dot_net_framework_latest"]
    not azure_issue["app_service_dot_net_framework_latest"]
}

app_service_dot_net_framework_latest {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_dot_net_framework_latest"]
    not azure_issue["app_service_dot_net_framework_latest"]
}

app_service_dot_net_framework_latest = false {
    azure_issue["app_service_dot_net_framework_latest"]
}

app_service_dot_net_framework_latest_err = "Azure App Service currently dont have latest version of Dot Net Framework" {
    azure_issue["app_service_dot_net_framework_latest"]
}

app_service_dot_net_framework_latest_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-013",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service Dot Net Framework should be latest",
    "Policy Description": "This policy will identify the Azure app service which dont have latest version of Dot Net Framework and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-014
#

default app_service_php_version_latest = null

latest_php_version := 7.4

azure_attribute_absence["app_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

azure_attribute_absence["app_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.php_version
}

azure_issue["app_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    to_number(site_config.php_version) != latest_php_version
}

# we need to make it pass if property is missing, as azurerm_app_service may not need php
app_service_php_version_latest {
    lower(input.resources[_].type) == "azurerm_app_service"
    azure_attribute_absence["app_service_php_version_latest"]
    not azure_issue["app_service_php_version_latest"]
}

app_service_php_version_latest {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_php_version_latest"]
    not azure_issue["app_service_php_version_latest"]
}

app_service_php_version_latest = false {
    azure_issue["app_service_php_version_latest"]
}

app_service_php_version_latest_err = "Azure App Service currently dont have latest version of PHP" {
    azure_issue["app_service_php_version_latest"]
}

app_service_php_version_latest_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service PHP version should be latest",
    "Policy Description": "This policy will identify the Azure app service which dont have latest version of PHP and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-015
#

default app_service_python_version_latest = null

latest_python_version_three := 3.9
latest_python_version_two := 2.7

azure_attribute_absence["app_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

azure_attribute_absence["app_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.python_version
}

azure_issue["app_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    to_number(site_config.python_version) != latest_python_version_three
    to_number(site_config.python_version) != latest_python_version_two
}

# we need to make it pass if property is missing, as azurerm_app_service may not need python
app_service_python_version_latest {
    lower(input.resources[_].type) == "azurerm_app_service"
    azure_attribute_absence["app_service_python_version_latest"]
    not azure_issue["app_service_python_version_latest"]
}

app_service_python_version_latest {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_python_version_latest"]
    not azure_issue["app_service_python_version_latest"]
}

app_service_python_version_latest = false {
    azure_issue["app_service_python_version_latest"]
}

app_service_python_version_latest_err = "Azure App Service currently dont have latest version of Python" {
    azure_issue["app_service_python_version_latest"]
}

app_service_python_version_latest_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-015",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service Pyhton version should be latest",
    "Policy Description": "This policy will identify the Azure app service which dont have latest version of Pyhton and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-016
#

default app_service_java_version_latest = null

# valid values are 1.7.0_80, 1.8.0_181, 11
latest_java_version := "11"

azure_attribute_absence["app_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.site_config
}

azure_attribute_absence["app_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    not site_config.java_version
}

# valid values are 1.7.0_80, 1.8.0_181, 11
azure_issue["app_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    site_config := resource.properties.site_config[_]
    site_config.java_version != latest_java_version
}

# we need to make it pass if property is missing, as azurerm_app_service may not need java
app_service_java_version_latest {
    lower(input.resources[_].type) == "azurerm_app_service"
    azure_attribute_absence["app_service_java_version_latest"]
    not azure_issue["app_service_java_version_latest"]
}

app_service_java_version_latest {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_java_version_latest"]
    not azure_issue["app_service_java_version_latest"]
}

app_service_java_version_latest = false {
    azure_issue["app_service_java_version_latest"]
}

app_service_java_version_latest_err = "Azure App Service currently dont have latest version of Java" {
    azure_issue["app_service_java_version_latest"]
}

app_service_java_version_latest_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-016",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service Java version should be latest",
    "Policy Description": "This policy will identify the Azure app service which dont have latest version of Java and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}


#
# PR-AZR-TRF-WEB-017
#
# As per Farshid: it is not required for all the azure app service to use storage
# but if they are using, then they should use Azure Files
# it means the only time we fail the test is when lower(storage_account.type) != "azurefiles"
# if it is not present, the test will pass

default app_service_storage_account_type_azurefile = null

azure_attribute_absence["app_service_storage_account_type_azurefile"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.storage_account
}

azure_issue["app_service_storage_account_type_azurefile"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    storage_account := resource.properties.storage_account[_]
    not storage_account.type
}

azure_issue["app_service_storage_account_type_azurefile"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    storage_account := resource.properties.storage_account[_]
    lower(storage_account.type) != "azurefiles"
}

app_service_storage_account_type_azurefile {
	lower(input.resources[_].type) == "azurerm_app_service"
    azure_attribute_absence["app_service_storage_account_type_azurefile"]
    not azure_issue["app_service_storage_account_type_azurefile"]
}

app_service_storage_account_type_azurefile {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_storage_account_type_azurefile"]
    not azure_issue["app_service_storage_account_type_azurefile"]
}

app_service_storage_account_type_azurefile = false {
    azure_issue["app_service_storage_account_type_azurefile"]
}

app_service_storage_account_type_azurefile_err = "Azure App Service storage account type is currently not AzureFiles" {
    azure_issue["app_service_storage_account_type_azurefile"]
}

app_service_storage_account_type_azurefile_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-017",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure App Service storage account type should be AzureFiles",
    "Policy Description": "This policy will identify the Azure app service which dont have storage account type AzureFiles and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}

#
# PR-AZR-TRF-WEB-018
#

default app_service_aad_auth_enabled = null

azure_attribute_absence["app_service_aad_auth_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    not resource.properties.auth_settings
}

azure_attribute_absence["app_service_aad_auth_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_app_service"
    auth_settings := resource.properties.auth_settings[_]
    not auth_settings.active_directory
}

app_service_aad_auth_enabled = false {
    azure_attribute_absence["app_service_aad_auth_enabled"]
}

app_service_aad_auth_enabled {
    lower(input.resources[_].type) == "azurerm_app_service"
    not azure_attribute_absence["app_service_aad_auth_enabled"]
}

app_service_aad_auth_enabled_err = "Azure App Service AAD authentication is currently not enabled" {
    azure_attribute_absence["app_service_aad_auth_enabled"]
}

app_service_aad_auth_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-WEB-018",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure App Service AAD authentication is enabled",
    "Policy Description": "This policy will identify the Azure app service which dont have AAD authentication enabled and give alert",
    "Resource Type": "azurerm_app_service",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service"
}
