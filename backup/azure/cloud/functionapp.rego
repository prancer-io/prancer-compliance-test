package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites

# PR-AZR-CLD-AFA-001

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
    #lower(input.resources[_].type) == "microsoft.web/sites"
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_attribute_absence["https_only"]
    not azure_issue["https_only"]
}

https_only = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["https_only"]
}

https_only = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["https_only"]
}

https_only_err = "Microsoft.web/Sites resource property httpsOnly missing in the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["https_only"]
} else = "Azure Function App currently does not redirect HTTP to HTTPS" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["https_only"]
}

https_only_metadata := {
    "Policy Code": "PR-AZR-CLD-AFA-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure Function App enforce https connection",
    "Policy Description": "This policy identifies Azure Function App which doesn't redirect HTTP to HTTPS. Azure Function App can be accessed by anyone using non-secure HTTP links by default. Non-secure HTTP requests can be restricted and all HTTP requests redirected to the secure HTTPS port. It is recommended to enforce HTTPS-only traffic.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-AFA-002

default min_tls_version = null

azure_attribute_absence ["min_tls_version"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

# azure_attribute_absence["min_tls_version"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.web/sites/config"
#     not resource.dependsOn
# }

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
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
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
    #lower(input.resources[_].type) == "microsoft.web/sites"
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_attribute_absence["min_tls_version"]
    not azure_issue["min_tls_version"]
}

min_tls_version {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_inner_attribute_absence["min_tls_version"]
    not azure_inner_issue["min_tls_version"]
}

min_tls_version {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["min_tls_version"]
    azure_inner_attribute_absence["min_tls_version"]
}

min_tls_version = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_attribute_absence["min_tls_version"]
    not azure_inner_attribute_absence["min_tls_version"]
    azure_issue["min_tls_version"]
    azure_inner_issue["min_tls_version"]
}

min_tls_version = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_inner_attribute_absence["min_tls_version"]
    not azure_attribute_absence["min_tls_version"]
    azure_issue["min_tls_version"]
}

min_tls_version = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["min_tls_version"]
    not azure_inner_attribute_absence["min_tls_version"]
    azure_inner_issue["min_tls_version"]
}

min_tls_version_err = "Azure Function App currently not configured with latest version TLS" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_attribute_absence["min_tls_version"]
    not azure_inner_attribute_absence["min_tls_version"]
    azure_issue["min_tls_version"]
    azure_inner_issue["min_tls_version"]
} else = "Azure Function App currently not configured with latest version TLS" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_inner_attribute_absence["min_tls_version"]
    not azure_attribute_absence["min_tls_version"]
    azure_issue["min_tls_version"]
} else = "Azure Function App currently not configured with latest version TLS" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["min_tls_version"]
    not azure_inner_attribute_absence["min_tls_version"]
    azure_inner_issue["min_tls_version"]
}

min_tls_version_metadata := {
    "Policy Code": "PR-AZR-CLD-AFA-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Function App should use the latest version of TLS encryption",
    "Policy Description": "This policy identifies Azure Function App which are not set with latest version of TLS encryption. Azure currently allows the Function App to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for Function App secure connections.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-AFA-003

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
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_attribute_absence["client_cert_enabled"]
    not azure_issue["client_cert_enabled"]
}

client_cert_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["client_cert_enabled"]
}

client_cert_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["client_cert_enabled"]
}

client_cert_enabled_err = "microsoft.web/sites resource property clientCertEnabled missing in the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["client_cert_enabled"]
} else = "Azure Function App does not have incoming client certificates enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["client_cert_enabled"]
}

client_cert_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-AFA-003",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Function App should have incoming client certificates enabled",
    "Policy Description": "This policy identifies Azure Function App which are not set with client certificate. Client certificates allow for the app to request a certificate for incoming requests. Only clients that have a valid certificate will be able to reach the app.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-AFA-004

default http_20_enabled = null

azure_attribute_absence ["http_20_enabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

# azure_attribute_absence["http_20_enabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.web/sites/config"
#     not resource.dependsOn
# }

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
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
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
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_attribute_absence["http_20_enabled"]
    not azure_issue["http_20_enabled"]
}

http_20_enabled {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_inner_attribute_absence["http_20_enabled"]
    not azure_inner_issue["http_20_enabled"]
}

http_20_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["http_20_enabled"]
    azure_inner_attribute_absence["http_20_enabled"]
}

http_20_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["http_20_enabled"]
    azure_inner_issue["http_20_enabled"]
}

http_20_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_inner_attribute_absence["http_20_enabled"]
    azure_issue["http_20_enabled"]
}

http_20_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["http_20_enabled"]
    azure_inner_issue["http_20_enabled"]
}

http_20_enabled_err = "Azure Function App currently not using latest version of HTTP protocol" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["http_20_enabled"]
    azure_inner_issue["http_20_enabled"]
} else = "microsoft.web/sites resource property siteConfig.http20Enabled is missing from the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["http_20_enabled"]
    azure_inner_attribute_absence["http_20_enabled"]
} else = "microsoft.web/sites resource property siteConfig.http20Enabled is missing from the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_inner_attribute_absence["http_20_enabled"]
    azure_issue["http_20_enabled"]
} else = "microsoft.web/sites resource property siteConfig.http20Enabled is missing from the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["http_20_enabled"]
    azure_inner_issue["http_20_enabled"]
}

http_20_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-AFA-004",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Function App should use the latest version of HTTP",
    "Policy Description": "This policy identifies Azure Function App which doesn't use HTTP 2.0. HTTP 2.0 has additional performance improvements on the head-of-line blocking problem of old HTTP version, header compression, and prioritisation of requests. HTTP 2.0 no longer supports HTTP 1.1's chunked transfer encoding mechanism, as it provides its own, more efficient, mechanisms for data streaming.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-AFA-005

default azure_function_app_has_auth_settings_enabled = null

azure_attribute_absence ["azure_function_app_has_auth_settings_enabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.web/sites/config"; c := 1]) == 0
}

# azure_attribute_absence["azure_function_app_has_auth_settings_enabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.web/sites/config"
#     not resource.dependsOn
# }

# azure_attribute_absence["azure_function_app_has_auth_settings_enabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.web/sites/config"
#     not resource.name
# }

# azure_attribute_absence["azure_function_app_has_auth_settings_enabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.web/sites/config"
#     not resource.properties.enabled
# }

azure_issue["azure_function_app_has_auth_settings_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.web/sites/config";
              lower(r.name) == "authsettings";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.enabled == true;
              c := 1]) == 0
}

azure_function_app_has_auth_settings_enabled {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_attribute_absence["azure_function_app_has_auth_settings_enabled"]
    not azure_issue["azure_function_app_has_auth_settings_enabled"]
}

azure_function_app_has_auth_settings_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["azure_function_app_has_auth_settings_enabled"]
}

azure_function_app_has_auth_settings_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["azure_function_app_has_auth_settings_enabled"]
}

azure_function_app_has_auth_settings_enabled_err = "Azure Function App currently not have authentication enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["azure_function_app_has_auth_settings_enabled"]
} else = "microsoft.web/sites/config resource property enabled is missing from the resource. Make sure to set vaule as 'true' after property added to the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["azure_function_app_has_auth_settings_enabled"]
}

azure_function_app_has_auth_settings_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-AFA-005",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Function App authentication should be enabled",
    "Policy Description": "This policy identifies Azure Function App which has set authentication to off. Azure Function App Authentication is a feature that can prevent anonymous HTTP requests from reaching the API app, or authenticate those that have tokens before they reach the API app. If an anonymous request is received from a browser, Function App will redirect to a logon page. To handle the logon process, a choice from a set of identity providers can be made, or a custom authentication mechanism can be implemented.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}


# PR-AZR-CLD-AFA-006

default functionapp_managed_identity_provider_enabled = null

azure_attribute_absence["functionapp_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.identity
}

azure_attribute_absence["functionapp_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not resource.identity.type
}

azure_issue ["functionapp_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not contains(lower(resource.identity.type), "systemassigned")
}

azure_issue ["functionapp_managed_identity_provider_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    not contains(lower(resource.identity.type), "userassigned")
}

functionapp_managed_identity_provider_enabled {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    not azure_attribute_absence["functionapp_managed_identity_provider_enabled"]
    not azure_issue["functionapp_managed_identity_provider_enabled"]
}

functionapp_managed_identity_provider_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["functionapp_managed_identity_provider_enabled"]
}

functionapp_managed_identity_provider_enabled = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["functionapp_managed_identity_provider_enabled"]
}

functionapp_managed_identity_provider_enabled_err = "microsoft.web/sites property 'identity.type' need to be exist. Its missing from the resource." {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_attribute_absence["functionapp_managed_identity_provider_enabled"]
} else = "Azure Function App currently dont have any identity provider enabled" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.web/sites"
    contains(lower(resource.kind), "functionapp")
    azure_issue["functionapp_managed_identity_provider_enabled"]
}

web_service_managed_identity_provider_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-AFA-006",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Function App Managed Identity provider should be enabled",
    "Policy Description": "This policy identifies Azure Function App which doesn't have a Managed Service Identity. Managed service identity in Function App makes the app more secure by eliminating secrets from the app, such as credentials in the connection strings. When registering with Azure Active Directory in the app service, the app will connect to other Azure services securely without the need of username and passwords.",
    "Resource Type": "microsoft.web/sites",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.web/sites"
}
