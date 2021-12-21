package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites

# PR-AZR-CLD-WEB-001

default https_only = null

azure_attribute_absence ["https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.httpsOnly
}


azure_issue ["https_only"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.httpsOnly != true
}


https_only {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["https_only"]
    not azure_issue["https_only"]
}


https_only = false {
    azure_attribute_absence["https_only"]
}

https_only = false {
    azure_issue["https_only"]
}

https_only_err = "Microsoft.web/Sites resource property httpsOnly missing in the resource" {
    azure_attribute_absence["https_only"]
} else = "Azure App Service Web app does not redirect HTTP to HTTPS" {
    azure_issue["https_only"]
}

https_only_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure App Service Web App enforce https connection",
    "Policy Description": "Azure Web Apps by default allows sites to run under both HTTP and HTTPS, and can be accessed by anyone using non-secure HTTP links. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. We recommend you enforce HTTPS-only traffic to increase security. This will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-WEB-002

default min_tls_version = null

azure_attribute_absence ["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.minTlsVersion
}

azure_issue ["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.minTlsVersion != "1.2"
}


min_tls_version {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["min_tls_version"]
    not azure_issue["min_tls_version"]
}

min_tls_version = false {
    azure_attribute_absence["min_tls_version"]
}

min_tls_version = false {
    azure_issue["min_tls_version"]
}

min_tls_version_err = "microsoft.web/sites resource property minTlsVersion missing in the resource" {
    azure_attribute_absence["min_tls_version"]
} else = "Web App does not use the latest version of TLS encryption" {
    azure_issue["min_tls_version"]
}

min_tls_version_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Web App should uses the latest version of TLS encryption",
    "Policy Description": "App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. For secure web app connections it is highly recommended to only use the latest TLS 1.2 version.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}




# PR-AZR-CLD-WEB-003

default client_cert_enabled = null

azure_attribute_absence ["client_cert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.clientCertEnabled
}

azure_issue ["client_cert_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.clientCertEnabled != true
}


client_cert_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["client_cert_enabled"]
    not azure_issue["client_cert_enabled"]
}

client_cert_enabled = false {
    azure_attribute_absence["client_cert_enabled"]
}

client_cert_enabled = false {
    azure_issue["client_cert_enabled"]
}

client_cert_enabled_err = "microsoft.web/sites resource property clientCertEnabled missing in the resource" {
    azure_attribute_absence["client_cert_enabled"]
} else = "Web App does not have incoming client certificates enabled" {
    azure_issue["client_cert_enabled"]
}

client_cert_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Web App should has incoming client certificates enabled",
    "Policy Description": "Client certificates allow the Web App to require a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app. The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}





# PR-AZR-CLD-WEB-004

default http_20_enabled = null

azure_attribute_absence ["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.http20Enabled
}


azure_issue ["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.http20Enabled != true
}


http_20_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["http_20_enabled"]
    not azure_issue["http_20_enabled"]
}

http_20_enabled = false {
    azure_attribute_absence["http_20_enabled"]
}

http_20_enabled = false {
    azure_issue["http_20_enabled"]
}

http_20_enabled_err = "microsoft.web/sites resource property http20Enabled missing in the resource" {
    azure_attribute_absence["http_20_enabled"]
} else = "Web App does not use the latest version of HTTP" {
    azure_issue["http_20_enabled"]
}

http_20_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Web App should uses the latest version of HTTP",
    "Policy Description": "We recommend you use the latest HTTP version for web apps and take advantage of any security fixes and new functionalities featured. With each software installation you can determine if a given update meets your organization's requirements. Organizations should verify the compatibility and support provided for any additional software, assessing the current version against the update revision being considered.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-WEB-006
#

default web_service_cors_not_allowing_all = null

azure_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}



azure_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.cors
}

azure_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.cors.allowedOrigins
}


azure_issue["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    allowedOrigin := resource.properties.siteConfig.cors.allowedOrigins[_]
    contains(allowedOrigin, "*")
}


web_service_cors_not_allowing_all {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_cors_not_allowing_all"]
    not azure_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_cors_not_allowing_all"]
    not azure_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all = false {
    azure_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all_err = "CORS configuration is currently allowing every resources to access Azure Web Service" {
    azure_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure CORS configuration is not allowing every resources to access Azure Web Service",
    "Policy Description": "This policy will identify CORS configuration which are allowing every resoruces to access Azure Web service and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-WEB-007
#

default web_service_http_logging_enabled = null

azure_attribute_absence["web_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.httpLoggingEnabled
}


azure_issue["web_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.httpLoggingEnabled != true
}


web_service_http_logging_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_http_logging_enabled"]
    not azure_issue["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled = false {
    azure_attribute_absence["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled = false {
    azure_issue["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled_err = "Azure Web Service http logging currently is disable" {
    azure_issue["web_service_http_logging_enabled"]
} else = "microsoft.web/sites property 'siteConfig.httpLoggingEnabled' need to be exist. Its missing from the resource.e" {
    azure_attribute_absence["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-007",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service http logging should be enabled",
    "Policy Description": "This policy will identify the Azure Web service which dont have http logging enabled and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-WEB-008
#

default web_service_detaild_error_message_enabled = null

azure_attribute_absence["web_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.detailedErrorLoggingEnabled
}


azure_issue["web_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.detailedErrorLoggingEnabled != true
}


web_service_detaild_error_message_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_detaild_error_message_enabled"]
    not azure_issue["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled = false {
    azure_attribute_absence["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled = false {
    azure_issue["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled_err = "Azure Web Service detaild error message currently not enabled" {
    azure_issue["web_service_detaild_error_message_enabled"]
} else = "microsoft.web/sites property 'siteConfig.detailedErrorLoggingEnabled' need to be exist. Its missing from the resource." {
    azure_attribute_absence["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service detaild error message should be enabled",
    "Policy Description": "This policy will identify the Azure Web service which dont have detaild error message enabled and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-WEB-009
#

default web_service_request_tracing_enabled = null

azure_attribute_absence["web_service_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.requestTracingEnabled
}

azure_issue["web_service_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.requestTracingEnabled != true
}


web_service_request_tracing_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_request_tracing_enabled"]
    not azure_issue["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled = false {
    azure_attribute_absence["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled = false {
    azure_issue["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled_err = "Azure Web Service Failed request tracing currently not enabled" {
    azure_issue["web_service_request_tracing_enabled"]
} else = "microsoft.web/sites property 'siteConfig.requestTracingEnabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service Failed request tracing should be enabled",
    "Policy Description": "This policy will identify the Azure Web service which dont have request tracing enabled and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-WEB-010

default web_service_managed_identity_provider_enabled = null

azure_attribute_absence["web_service_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.identity
}


azure_attribute_absence["web_service_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.identity.type
}


web_service_managed_identity_provider_enabled = false {
    azure_attribute_absence["web_service_managed_identity_provider_enabled"]
} else = true {
    lower(input.resources[_].type) == "microsoft.web/sites"
}

web_service_managed_identity_provider_enabled_err = "microsoft.web/sites property 'identity.type' need to be exist. Its missing from the resource." {
    azure_attribute_absence["web_service_managed_identity_provider_enabled"]
}

web_service_managed_identity_provider_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-010",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service Managed Identity provider should be enabled",
    "Policy Description": "This policy will identify the Azure web service which dont have Managed Identity provider enabled and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-WEB-011

default web_service_remote_debugging_disabled = null

azure_attribute_absence["web_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.remoteDebuggingEnabled
}


azure_issue["web_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.remoteDebuggingEnabled != false
}



web_service_remote_debugging_disabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_remote_debugging_disabled"]
    not azure_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled = false {
    azure_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled_err = "Azure Web Service remote debugging currently not disabled" {
    azure_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-011",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service remote debugging should be disabled",
    "Policy Description": "This policy will identify the Azure web service which have remote debugging enabled and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-WEB-012
#

default web_service_ftp_deployment_disabled = null

azure_attribute_absence["web_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.ftpsState
}


azure_issue["web_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.ftpsState
    lower(resource.properties.siteConfig.ftpsState) != "disabled"
    lower(resource.properties.siteConfig.ftpsState) != "ftpsonly"
}

web_service_ftp_deployment_disabled = false {
    azure_attribute_absence["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_ftp_deployment_disabled"]
    not azure_issue["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled = false {
    azure_issue["web_service_ftp_deployment_disabled"]
}



web_service_ftp_deployment_disabled_err = "Azure Web Service FTP deployment is currently not disabled" {
    azure_issue["web_service_ftp_deployment_disabled"]
} else = "microsoft.web/sites property 'siteConfig.ftpsState' need to be exist. Its missing from the resource." {
    azure_attribute_absence["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-012",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service FTP deployments should be disabled",
    "Policy Description": "This policy will identify the Azure Web service which have FTP deployment enabled and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}

# PR-AZR-CLD-WEB-013
#

default web_service_net_framework_latest = null

#Defaults to v4.0
latest_dotnet_framework_version := "v6.0"

azure_attribute_absence["web_service_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.netFrameworkVersion
}


azure_issue["web_service_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    lower(resource.properties.siteConfig.netFrameworkVersion) != latest_dotnet_framework_version
}

# we need to make it pass if property is missing, as microsoft.web/sites may not need dot net framework
web_service_net_framework_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_net_framework_latest"]
    not azure_issue["web_service_net_framework_latest"]
}

web_service_net_framework_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_net_framework_latest"]
    not azure_issue["web_service_net_framework_latest"]
}

web_service_net_framework_latest = false {
    azure_issue["web_service_net_framework_latest"]
}

web_service_det_framework_latest_err = "Azure web Service currently dont have latest version of Dot Net Framework" {
    azure_issue["web_service_net_framework_latest"]
}

web_service_dot_neamework_latest_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-013",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure web Service Dot Net Framework should be latest",
    "Policy Description": "This policy will identify the Azure web service which dont have latest version of Net Framework and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


#
# PR-AZR-CLD-WEB-014
#

default web_service_php_version_latest = null

latest_php_version := 7.4

azure_attribute_absence["web_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.phpVersion
}


azure_issue["web_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    to_number(resource.properties.siteConfig.phpVersion) != latest_php_version
}


# we need to make it pass if property is missing, as microsoft.web/sites may not need php
web_service_php_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_php_version_latest"]
    not azure_issue["web_service_php_version_latest"]
}

web_service_php_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_php_version_latest"]
    not azure_issue["web_service_php_version_latest"]
}

web_service_php_version_latest = false {
    azure_issue["web_service_php_version_latest"]
}

web_service_php_version_latest_err = "Azure Web Service currently dont have latest version of PHP" {
    azure_issue["web_service_php_version_latest"]
}

web_service_php_version_latest_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-014",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service PHP version should be latest",
    "Policy Description": "This policy will identify the Azure web service which dont have latest version of PHP and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


#
# PR-AZR-CLD-WEB-015
#

default web_service_python_version_latest = null

latest_python_version_three := 3.9
latest_python_version_two := 2.7

azure_attribute_absence["web_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.pythonVersion
}



azure_issue["web_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    to_number(resource.properties.siteConfig.pythonVersion) != latest_python_version_three
    to_number(resource.properties.siteConfig.pythonVersion) != latest_python_version_two
}


# we need to make it pass if property is missing, as microsoft.web/sites may not need python
web_service_python_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_python_version_latest"]
    not azure_issue["web_service_python_version_latest"]
}

web_service_python_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_python_version_latest"]
    not azure_issue["web_service_python_version_latest"]
}

web_service_python_version_latest = false {
    azure_issue["web_service_python_version_latest"]
}

web_service_python_version_latest_err = "Azure Web Service currently dont have latest version of Python" {
    azure_issue["web_service_python_version_latest"]
}

web_service_python_version_latest_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-015",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service Pyhton version should be latest",
    "Policy Description": "This policy will identify the Azure web service which dont have latest version of Pyhton and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


#
# PR-AZR-CLD-WEB-016
#

default web_service_java_version_latest = null

# valid values are 1.7.0_80, 1.8.0_181, 11
latest_java_version := "11"

azure_attribute_absence["web_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.javaVersion
}


# valid values are 1.7.0_80, 1.8.0_181, 11
azure_issue["web_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.javaVersion != latest_java_version
}


# we need to make it pass if property is missing, as microsoft.web/sites may not need java
web_service_java_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_java_version_latest"]
    not azure_issue["web_service_java_version_latest"]
}

web_service_java_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_java_version_latest"]
    not azure_issue["web_service_java_version_latest"]
}

web_service_java_version_latest = false {
    azure_issue["web_service_java_version_latest"]
}

web_service_java_version_latest_err = "Azure Web Service currently dont have latest version of Java" {
    azure_issue["web_service_java_version_latest"]
}

web_service_java_version_latest_metadata := {
    "Policy Code": "PR-AZR-CLD-WEB-016",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Web Service Java version should be latest",
    "Policy Description": "This policy will identify the Azure web service which dont have latest version of Java and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}
