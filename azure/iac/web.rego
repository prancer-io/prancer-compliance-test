package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites

# PR-AZR-ARM-WEB-001

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
    "Policy Code": "PR-AZR-ARM-WEB-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure App Service Web App enforce https connection",
    "Policy Description": "Azure Web Apps by default allow sites to run under both HTTP and HTTPS and can be accessed by anyone using non-secure HTTP links. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. We recommend you enforce HTTPS-only traffic to increase security. This will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the SSL/TLS protocol to provide a secure connection, which is both encrypted and authenticated.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-002

default min_tls_version = null

azure_attribute_absence ["min_tls_version"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.minTlsVersion
}

azure_issue["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.minTlsVersion) == "1.2";
              c := 1]) == 0
}

azure_inner_attribute_absence ["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence ["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.minTlsVersion
}

azure_inner_issue ["min_tls_version"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.minTlsVersion != "1.2"
}

min_tls_version {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["min_tls_version"]
    not azure_issue["min_tls_version"]
}

min_tls_version {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["min_tls_version"]
    not azure_inner_issue["min_tls_version"]
}

min_tls_version = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["min_tls_version"]
    azure_inner_attribute_absence["min_tls_version"]
}

min_tls_version = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["min_tls_version"]
    azure_inner_issue["min_tls_version"]
}

min_tls_version = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["min_tls_version"]
    azure_issue["min_tls_version"]
}

min_tls_version = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["min_tls_version"]
    azure_inner_issue["min_tls_version"]
}

min_tls_version_err = "Web App currently not configured with latest version TLS" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["min_tls_version"]
    azure_inner_issue["min_tls_version"]
} else = "microsoft.web/sites resource property config.minTlsVersion is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["min_tls_version"]
    azure_inner_attribute_absence["min_tls_version"]
} else = "microsoft.web/sites resource property config.minTlsVersion is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["min_tls_version"]
    azure_issue["min_tls_version"]
} else = "microsoft.web/sites resource property config.minTlsVersion is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["min_tls_version"]
    azure_inner_issue["min_tls_version"]
}

min_tls_version_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Web App should use the latest version of TLS encryption",
    "Policy Description": "App service currently allows the web app to set TLS versions 1.0, 1.1, and 1.2. For secure web app connections, it is highly recommended to only use the latest TLS 1.2 version.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-003

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
    "Policy Code": "PR-AZR-ARM-WEB-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Web App should have incoming client certificates enabled",
    "Policy Description": "Client certificates allow the Web App to require a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app. The TLS mutual authentication technique in enterprise environments ensures the authenticity of clients to the server. If incoming client certificates are enabled only an authenticated client with valid certificates can access the app.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-004

default http_20_enabled = null

azure_attribute_absence ["http_20_enabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.http20Enabled
}

azure_issue["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.http20Enabled == true;
              c := 1]) == 0
}

azure_inner_attribute_absence ["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence ["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.http20Enabled
}

azure_inner_issue ["http_20_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.http20Enabled != true
}

http_20_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["http_20_enabled"]
    not azure_issue["http_20_enabled"]
}

http_20_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["http_20_enabled"]
    not azure_inner_issue["http_20_enabled"]
}

http_20_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["http_20_enabled"]
    azure_inner_attribute_absence["http_20_enabled"]
}

http_20_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["http_20_enabled"]
    azure_inner_issue["http_20_enabled"]
}

http_20_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["http_20_enabled"]
    azure_issue["http_20_enabled"]
}

http_20_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["http_20_enabled"]
    azure_inner_issue["http_20_enabled"]
}

http_20_enabled_err = "Web App currently not using latest version of HTTP protocol" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["http_20_enabled"]
    azure_inner_issue["http_20_enabled"]
} else = "microsoft.web/sites resource property siteConfig.http20Enabled is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["http_20_enabled"]
    azure_inner_attribute_absence["http_20_enabled"]
} else = "microsoft.web/sites resource property siteConfig.http20Enabled is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["http_20_enabled"]
    azure_issue["http_20_enabled"]
} else = "microsoft.web/sites resource property siteConfig.http20Enabled is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["http_20_enabled"]
    azure_inner_issue["http_20_enabled"]
}

http_20_enabled_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Web App should use the latest version of HTTP",
    "Policy Description": "We recommend you use the latest HTTP version for web apps and take advantage of any security fixes and new functionalities featured. With each software installation you can determine if a given update meets your organization's requirements. Organizations should verify the compatibility and support provided for any additional software, assessing the current version against the update revision being considered.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-006
#

default web_service_cors_not_allowing_all = null

azure_attribute_absence ["web_service_cors_not_allowing_all"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.cors
}

azure_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.cors.allowedOrigins
}

azure_issue["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              array_contains(r.properties.cors.allowedOrigins, "*");
              c := 1]) > 0
}

azure_inner_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.cors
}

azure_inner_attribute_absence["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.cors.allowedOrigins
}

azure_inner_issue["web_service_cors_not_allowing_all"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    allowedOrigin := resource.properties.siteConfig.cors.allowedOrigins[_]
    allowedOrigin == "*"
}

web_service_cors_not_allowing_all {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_cors_not_allowing_all"]
    not azure_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_cors_not_allowing_all"]
    not azure_inner_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_cors_not_allowing_all"]
    azure_inner_attribute_absence["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_cors_not_allowing_all"]
    azure_inner_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_cors_not_allowing_all"]
    azure_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_cors_not_allowing_all"]
    azure_inner_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all_err = "CORS configuration is currently allowing every resources to access Azure Web Service" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_cors_not_allowing_all"]
    azure_inner_issue["web_service_cors_not_allowing_all"]
} else = "CORS configuration is currently allowing every resources to access Azure Web Service" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_cors_not_allowing_all"]
    azure_issue["web_service_cors_not_allowing_all"]
} else = "CORS configuration is currently allowing every resources to access Azure Web Service" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_cors_not_allowing_all"]
    azure_inner_issue["web_service_cors_not_allowing_all"]
}

web_service_cors_not_allowing_all_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure CORS configuration is not allowing every resource to access Azure Web Service",
    "Policy Description": "This policy will identify CORS configuration which are allowing every resoruces to access Azure Web service and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-007
#

default web_service_http_logging_enabled = null

azure_attribute_absence ["web_service_http_logging_enabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.httpLoggingEnabled
}

azure_issue["web_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.httpLoggingEnabled == true;
              c := 1]) == 0
}

azure_inner_attribute_absence["web_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.httpLoggingEnabled
}

azure_inner_issue["web_service_http_logging_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.httpLoggingEnabled != true
}

web_service_http_logging_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_http_logging_enabled"]
    not azure_issue["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_http_logging_enabled"]
    not azure_inner_issue["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_http_logging_enabled"]
    azure_inner_attribute_absence["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_http_logging_enabled"]
    azure_inner_issue["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["web_service_http_logging_enabled"]
    azure_issue["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_http_logging_enabled"]
    azure_inner_issue["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled_err = "Azure Web Service http logging is currently not enabled" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_http_logging_enabled"]
    azure_inner_issue["web_service_http_logging_enabled"]
} else = "microsoft.web/sites property 'siteConfig.httpLoggingEnabled' need to be exist. Its missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_http_logging_enabled"]
    azure_inner_attribute_absence["web_service_http_logging_enabled"]
} else = "microsoft.web/sites property 'siteConfig.httpLoggingEnabled' need to be exist. Its missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["web_service_http_logging_enabled"]
    azure_issue["web_service_http_logging_enabled"]
} else = "microsoft.web/sites property 'siteConfig.httpLoggingEnabled' need to be exist. Its missing from the resource" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_http_logging_enabled"]
    azure_inner_issue["web_service_http_logging_enabled"]
}

web_service_http_logging_enabled_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service http logging should be enabled",
    "Policy Description": "This policy will identify the Azure Web service which don't have http logging enabled and give alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-008
#

default web_service_detaild_error_message_enabled = null

azure_attribute_absence ["web_service_detaild_error_message_enabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.detailedErrorLoggingEnabled
}

azure_issue["web_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.detailedErrorLoggingEnabled == true;
              c := 1]) == 0
}

azure_inner_attribute_absence["web_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.detailedErrorLoggingEnabled
}

azure_inner_issue["web_service_detaild_error_message_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.detailedErrorLoggingEnabled != true
}

web_service_detaild_error_message_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_detaild_error_message_enabled"]
    not azure_issue["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_detaild_error_message_enabled"]
    not azure_inner_issue["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_detaild_error_message_enabled"]
    azure_inner_attribute_absence["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_detaild_error_message_enabled"]
    azure_inner_issue["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["web_service_detaild_error_message_enabled"]
    azure_issue["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_detaild_error_message_enabled"]
    azure_inner_issue["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled_err = "Azure Web Service detaild error message is currently not enabled" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_detaild_error_message_enabled"]
    azure_inner_issue["web_service_detaild_error_message_enabled"]
} else = "microsoft.web/sites property 'siteConfig.detailedErrorLoggingEnabled' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_detaild_error_message_enabled"]
    azure_inner_attribute_absence["web_service_detaild_error_message_enabled"]
} else = "microsoft.web/sites property 'siteConfig.detailedErrorLoggingEnabled' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["web_service_detaild_error_message_enabled"]
    azure_issue["web_service_detaild_error_message_enabled"]
} else = "microsoft.web/sites property 'siteConfig.detailedErrorLoggingEnabled' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_detaild_error_message_enabled"]
    azure_inner_issue["web_service_detaild_error_message_enabled"]
}

web_service_detaild_error_message_enabled_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service detailed error message should be enabled",
    "Policy Description": "This policy will identify the Azure Web service which doesn't have a detailed error message enabled and give the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-009
#

default web_service_request_tracing_enabled = null

azure_attribute_absence ["web_service_request_tracing_enabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.requestTracingEnabled
}

azure_issue["web_service_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.requestTracingEnabled == true;
              c := 1]) == 0
}

azure_inner_attribute_absence["web_service_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.requestTracingEnabled
}

azure_inner_issue["web_service_request_tracing_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.requestTracingEnabled != true
}

web_service_request_tracing_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_request_tracing_enabled"]
    not azure_issue["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_request_tracing_enabled"]
    not azure_inner_issue["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_request_tracing_enabled"]
    azure_inner_attribute_absence["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_request_tracing_enabled"]
    azure_inner_issue["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["web_service_request_tracing_enabled"]
    azure_issue["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_request_tracing_enabled"]
    azure_inner_issue["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled_err = "Azure Web Service Failed request tracing is currently not enabled" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_request_tracing_enabled"]
    azure_inner_issue["web_service_request_tracing_enabled"]
} else = "microsoft.web/sites property 'siteConfig.requestTracingEnabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_request_tracing_enabled"]
    azure_inner_attribute_absence["web_service_request_tracing_enabled"]
} else = "microsoft.web/sites property 'siteConfig.requestTracingEnabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["web_service_request_tracing_enabled"]
    azure_issue["web_service_request_tracing_enabled"]
} else = "microsoft.web/sites property 'siteConfig.requestTracingEnabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_request_tracing_enabled"]
    azure_inner_issue["web_service_request_tracing_enabled"]
}

web_service_request_tracing_enabled_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service Failed request tracing should be enabled",
    "Policy Description": "This policy will identify the Azure web service which doesn't have request tracing enabled and give the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-010

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

web_service_managed_identity_provider_enabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_managed_identity_provider_enabled"]
}

web_service_managed_identity_provider_enabled = false {
    azure_attribute_absence["web_service_managed_identity_provider_enabled"]
}

web_service_managed_identity_provider_enabled_err = "microsoft.web/sites property 'identity.type' need to be exist. Its missing from the resource." {
    azure_attribute_absence["web_service_managed_identity_provider_enabled"]
}

web_service_managed_identity_provider_enabled_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-010",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service Managed Identity provider should be enabled",
    "Policy Description": "This policy will identify the Azure Web service which doesn't have Managed Identity provider enabled and give the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-011

default web_service_remote_debugging_disabled = null

azure_attribute_absence ["web_service_remote_debugging_disabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.remoteDebuggingEnabled
}

azure_issue["web_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.remoteDebuggingEnabled == true;
              c := 1]) > 0
}

azure_inner_attribute_absence["web_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.remoteDebuggingEnabled
}

azure_inner_issue["web_service_remote_debugging_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.remoteDebuggingEnabled != false
}

web_service_remote_debugging_disabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_remote_debugging_disabled"]
    not azure_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_remote_debugging_disabled"]
    not azure_inner_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_remote_debugging_disabled"]
    azure_inner_attribute_absence["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_remote_debugging_disabled"]
    azure_inner_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_remote_debugging_disabled"]
    azure_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_remote_debugging_disabled"]
    azure_inner_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled_err = "Azure Web Service remote debugging currently not disabled" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_remote_debugging_disabled"]
    azure_inner_issue["web_service_remote_debugging_disabled"]
} else = "Azure Web Service remote debugging currently not disabled" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_remote_debugging_disabled"]
    azure_issue["web_service_remote_debugging_disabled"]
} else = "Azure Web Service remote debugging currently not disabled" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_remote_debugging_disabled"]
    azure_inner_issue["web_service_remote_debugging_disabled"]
}

web_service_remote_debugging_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-011",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service remote debugging should be disabled",
    "Policy Description": "This policy will identify the Azure web service which has remote debugging enabled and give the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-ARM-WEB-012
#

default web_service_ftp_deployment_disabled = null

azure_attribute_absence ["web_service_ftp_deployment_disabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.ftpsState
}

azure_issue["web_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.ftpsState) != "disabled"
              lower(r.properties.ftpsState) != "ftpsonly"
              c := 1]) > 0
}

azure_inner_attribute_absence["web_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.ftpsState
}

azure_inner_issue["web_service_ftp_deployment_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.ftpsState
    lower(resource.properties.siteConfig.ftpsState) != "disabled"
    lower(resource.properties.siteConfig.ftpsState) != "ftpsonly"
}

web_service_ftp_deployment_disabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_ftp_deployment_disabled"]
    not azure_issue["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_ftp_deployment_disabled"]
    not azure_inner_issue["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_ftp_deployment_disabled"]
    azure_inner_attribute_absence["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_ftp_deployment_disabled"]
    azure_inner_issue["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["web_service_ftp_deployment_disabled"]
    azure_issue["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled = false {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_ftp_deployment_disabled"]
    azure_inner_issue["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled_err = "Azure Web Service FTP deployment is currently not disabled" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_ftp_deployment_disabled"]
    azure_inner_issue["web_service_ftp_deployment_disabled"]
} else = "microsoft.web/sites property 'siteConfig.ftpsState' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_ftp_deployment_disabled"]
    azure_inner_attribute_absence["web_service_ftp_deployment_disabled"]
} else = "microsoft.web/sites property 'siteConfig.ftpsState' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_inner_attribute_absence["web_service_ftp_deployment_disabled"]
    azure_issue["web_service_ftp_deployment_disabled"]
} else = "microsoft.web/sites property 'siteConfig.ftpsState' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_ftp_deployment_disabled"]
    azure_inner_issue["web_service_ftp_deployment_disabled"]
}

web_service_ftp_deployment_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-012",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service FTP deployments should be disabled",
    "Policy Description": "This policy will identify the Azure web service which has FTP deployment enabled and gives the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}

# PR-AZR-ARM-WEB-013
#

default web_service_net_framework_latest = null

#Defaults to v4.0
latest_dotnet_framework_version := "v6.0"
default_dotnet_framework_version := "v4.0"

azure_attribute_absence ["web_service_net_framework_latest"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.netFrameworkVersion
}

azure_issue["web_service_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.netFrameworkVersion) != latest_dotnet_framework_version;
              lower(r.properties.netFrameworkVersion) != default_dotnet_framework_version;
              c := 1]) > 0
}

azure_inner_attribute_absence["web_service_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.netFrameworkVersion
}

azure_inner_issue["web_service_net_framework_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    lower(resource.properties.siteConfig.netFrameworkVersion) != latest_dotnet_framework_version
    lower(resource.properties.siteConfig.netFrameworkVersion) != default_dotnet_framework_version
}

# we need to make it pass if property is missing, as microsoft.web/sites may not need dot net framework

web_service_net_framework_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_net_framework_latest"]
    not azure_issue["web_service_net_framework_latest"]
}

web_service_net_framework_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_net_framework_latest"]
    not azure_inner_issue["web_service_net_framework_latest"]
}

web_service_net_framework_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_net_framework_latest"]
    azure_inner_attribute_absence["web_service_net_framework_latest"]
}

web_service_net_framework_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_net_framework_latest"]
    azure_inner_issue["web_service_net_framework_latest"]
}

web_service_net_framework_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_net_framework_latest"]
    azure_issue["web_service_net_framework_latest"]
}

web_service_net_framework_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_net_framework_latest"]
    azure_inner_issue["web_service_net_framework_latest"]
}

web_service_net_framework_latest_err = "Azure web Service currently dont have latest version of Dot Net Framework" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_net_framework_latest"]
    azure_inner_issue["web_service_net_framework_latest"]
} else = "Azure web Service currently dont have latest version of Dot Net Framework" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_net_framework_latest"]
    azure_issue["web_service_net_framework_latest"]
} else = "Azure web Service currently dont have latest version of Dot Net Framework" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_net_framework_latest"]
    azure_inner_issue["web_service_net_framework_latest"]
}

web_service_dot_neamework_latest_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-013",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure web Service Dot Net Framework should be latest",
    "Policy Description": "This policy will identify the Azure web service which doesn't have the latest version of Net Framework and give the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


#
# PR-AZR-ARM-WEB-014
#

default web_service_php_version_latest = null

latest_php_version := 7.4

azure_attribute_absence ["web_service_php_version_latest"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.phpVersion
}

azure_issue["web_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              to_number(r.properties.phpVersion) != latest_php_version;
              c := 1]) > 0
}

azure_inner_attribute_absence["web_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.phpVersion
}

azure_inner_issue["web_service_php_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    to_number(resource.properties.siteConfig.phpVersion) != latest_php_version
}

# we need to make it pass if property is missing, as microsoft.web/sites may not need php

web_service_php_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_php_version_latest"]
    not azure_issue["web_service_php_version_latest"]
}

web_service_php_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_php_version_latest"]
    not azure_inner_issue["web_service_php_version_latest"]
}

web_service_php_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_php_version_latest"]
    azure_inner_attribute_absence["web_service_php_version_latest"]
}

web_service_php_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_php_version_latest"]
    azure_inner_issue["web_service_php_version_latest"]
}

web_service_php_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_php_version_latest"]
    azure_issue["web_service_php_version_latest"]
}

web_service_php_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_php_version_latest"]
    azure_inner_issue["web_service_php_version_latest"]
}

web_service_php_version_latest_err = "Azure Web Service currently dont have latest version of PHP" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_php_version_latest"]
    azure_inner_issue["web_service_php_version_latest"]
} else = "Azure Web Service currently dont have latest version of PHP" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_php_version_latest"]
    azure_issue["web_service_php_version_latest"]
} else = "Azure Web Service currently dont have latest version of PHP" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_php_version_latest"]
    azure_inner_issue["web_service_php_version_latest"]
}

web_service_php_version_latest_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service PHP version should be latest",
    "Policy Description": "This policy will identify the Azure web service which doesn't have the latest version of PHP and give the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


#
# PR-AZR-ARM-WEB-015
#

default web_service_python_version_latest = null

latest_python_version_three := 3.9
latest_python_version_two := 2.7

azure_attribute_absence ["web_service_python_version_latest"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.pythonVersion
}

azure_issue["web_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              to_number(r.properties.pythonVersion) != latest_python_version_three;
              to_number(r.properties.pythonVersion) != latest_python_version_two;
              c := 1]) > 0
}

azure_inner_attribute_absence["web_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.pythonVersion
}

azure_inner_issue["web_service_python_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    to_number(resource.properties.siteConfig.pythonVersion) != latest_python_version_three
    to_number(resource.properties.siteConfig.pythonVersion) != latest_python_version_two
}

# we need to make it pass if property is missing, as microsoft.web/sites may not need python

web_service_python_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_python_version_latest"]
    not azure_issue["web_service_python_version_latest"]
}

web_service_python_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_python_version_latest"]
    not azure_inner_issue["web_service_python_version_latest"]
}

web_service_python_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_python_version_latest"]
    azure_inner_attribute_absence["web_service_python_version_latest"]
}

web_service_python_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_python_version_latest"]
    azure_inner_issue["web_service_python_version_latest"]
}

web_service_python_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_python_version_latest"]
    azure_issue["web_service_python_version_latest"]
}

web_service_python_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_python_version_latest"]
    azure_inner_issue["web_service_python_version_latest"]
}

web_service_python_version_latest_err = "Azure Web Service currently dont have latest version of Python" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_python_version_latest"]
    azure_inner_issue["web_service_python_version_latest"]
} else = "Azure Web Service currently dont have latest version of Python" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_python_version_latest"]
    azure_issue["web_service_python_version_latest"]
} else = "Azure Web Service currently dont have latest version of Python" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_python_version_latest"]
    azure_inner_issue["web_service_python_version_latest"]
}

web_service_python_version_latest_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-015",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service Python version should be latest",
    "Policy Description": "This policy will identify the Azure web service which doesn't have the latest version of Python and give the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


#
# PR-AZR-ARM-WEB-016
#

default web_service_java_version_latest = null

# valid values are 1.7.0_80, 1.8.0_181, 11
latest_java_version := "11"

azure_attribute_absence ["web_service_java_version_latest"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

azure_attribute_absence["web_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.dependsOn
}

azure_attribute_absence["web_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites/config"
    not resource.properties.javaVersion
}

azure_issue["web_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.javaVersion != latest_java_version;
              c := 1]) > 0
}

azure_inner_attribute_absence["web_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig
}

azure_inner_attribute_absence["web_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.properties.siteConfig.javaVersion
}

azure_inner_issue["web_service_java_version_latest"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    resource.properties.siteConfig.javaVersion != latest_java_version
}

# we need to make it pass if property is missing, as microsoft.web/sites may not need java
web_service_java_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_attribute_absence["web_service_java_version_latest"]
    not azure_issue["web_service_java_version_latest"]
}

web_service_java_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    not azure_inner_attribute_absence["web_service_java_version_latest"]
    not azure_inner_issue["web_service_java_version_latest"]
}

web_service_java_version_latest {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_attribute_absence["web_service_java_version_latest"]
    azure_inner_attribute_absence["web_service_java_version_latest"]
}

web_service_java_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_java_version_latest"]
    azure_inner_issue["web_service_java_version_latest"]
}

web_service_java_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_java_version_latest"]
    azure_issue["web_service_java_version_latest"]
}

web_service_java_version_latest = false {
	lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_java_version_latest"]
    azure_inner_issue["web_service_java_version_latest"]
}

web_service_java_version_latest_err = "Azure Web Service currently dont have latest version of Java" {
    lower(input.resources[_].type) == "microsoft.web/sites"
    azure_issue["web_service_java_version_latest"]
    azure_inner_issue["web_service_java_version_latest"]
} else = "Azure Web Service currently dont have latest version of Java" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_inner_attribute_absence["web_service_java_version_latest"]
    azure_issue["web_service_java_version_latest"]
} else = "Azure Web Service currently dont have latest version of Java" {
    lower(input.resources[_].type) == "microsoft.web/sites"
 	azure_attribute_absence["web_service_java_version_latest"]
    azure_inner_issue["web_service_java_version_latest"]
}

web_service_java_version_latest_metadata := {
    "Policy Code": "PR-AZR-ARM-WEB-016",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Web Service Java version should be latest",
    "Policy Description": "This policy will identify the Azure web service which doesn't have the latest version of Java and give the alert",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}

