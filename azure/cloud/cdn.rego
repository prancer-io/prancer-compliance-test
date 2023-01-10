package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


# https://learn.microsoft.com/en-us/rest/api/cdn/custom-domains/create?tabs=HTTP#customdomain
#
# PR-AZR-CLD-CDN-001
#

default cdn_customdomain_configured_with_https = null

azure_attribute_absence["cdn_customdomain_configured_with_https"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cdn/profiles/endpoints/customdomains"
    not resource.properties.customHttpsProvisioningState
}

azure_issue["cdn_customdomain_configured_with_https"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cdn/profiles/endpoints/customdomains"
    lower(resource.properties.customHttpsProvisioningState) != "enabled"
}

cdn_customdomain_configured_with_https {
    lower(input.resources[_].type) == "microsoft.cdn/profiles/endpoints/customdomains"
    not azure_issue["cdn_customdomain_configured_with_https"]
    not azure_attribute_absence["cdn_customdomain_configured_with_https"]
}

cdn_customdomain_configured_with_https = false {
    azure_issue["cdn_customdomain_configured_with_https"]
}

cdn_customdomain_configured_with_https = false {
    azure_attribute_absence["cdn_customdomain_configured_with_https"]
}

cdn_customdomain_configured_with_https_err = "Azure CDN endpoint Custom domains currently not configured with HTTPS" {
    azure_issue["cdn_customdomain_configured_with_https"]
} else = "Azure CDN endpoint attribute customHttpsProvisioningState is missing from the resource" {
    azure_attribute_absence["cdn_customdomain_configured_with_https"]
}

cdn_customdomain_configured_with_https_metadata := {
    "Policy Code": "PR-AZR-CLD-CDN-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure CDN Endpoint Custom domains should be configured with HTTPS",
    "Policy Description": "This policy identifies Azure CDN Endpoint Custom domains which has not configured with HTTPS. Enabling HTTPS would allow sensitive data to be delivered securely via TLS/SSL encryption when it is sent across the internet. It is recommended to enable HTTPS in Azure CDN Endpoint Custom domains which will provide additional security and protects your web applications from attacks.",
    "Resource Type": "microsoft.cdn/profiles/endpoints/customdomains",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.cdn/profiles/endpoints/customdomains?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/rest/api/cdn/custom-domains/create?tabs=HTTP#cdnmanagedhttpsparameters
#
# PR-AZR-CLD-CDN-002
#

default cdn_customdomain_configured_with_secure_tls = null

azure_attribute_absence["cdn_customdomain_configured_with_secure_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cdn/profiles/endpoints/customdomains"
    not resource.properties.customHttpsParameters
}

azure_attribute_absence["cdn_customdomain_configured_with_secure_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cdn/profiles/endpoints/customdomains"
    not resource.properties.customHttpsParameters.minimumTlsVersion
}

azure_issue["cdn_customdomain_configured_with_secure_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.cdn/profiles/endpoints/customdomains"
    lower(resource.properties.customHttpsParameters.minimumTlsVersion) != "tls12"
}

cdn_customdomain_configured_with_secure_tls {
    lower(input.resources[_].type) == "microsoft.cdn/profiles/endpoints/customdomains"
    not azure_issue["cdn_customdomain_configured_with_secure_tls"]
    not azure_attribute_absence["cdn_customdomain_configured_with_secure_tls"]
}

cdn_customdomain_configured_with_secure_tls = false {
    azure_issue["cdn_customdomain_configured_with_secure_tls"]
}

cdn_customdomain_configured_with_secure_tls = false {
    azure_attribute_absence["cdn_customdomain_configured_with_secure_tls"]
}

cdn_customdomain_configured_with_secure_tls_err = "Azure CDN endpoint Custom domains currently not using secure tls" {
    azure_issue["cdn_customdomain_configured_with_secure_tls"]
} else = "Azure CDN endpoint attribute customHttpsParameters.minimumTlsVersion is missing from the resource" {
    azure_attribute_absence["cdn_customdomain_configured_with_secure_tls"]
}

cdn_customdomain_configured_with_secure_tls_metadata := {
    "Policy Code": "PR-AZR-CLD-CDN-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure CDN Endpoint Custom domains should use secure TLS version",
    "Policy Description": "This policy identifies Azure CDN Endpoint Custom domains which has insecure TLS version. TLS 1.2 resolves the security gap from its preceding versions. As a best security practice, use TLS 1.2 as the minimum TLS version for Azure CDN Endpoint Custom domains.",
    "Resource Type": "microsoft.cdn/profiles/endpoints/customdomains",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.cdn/profiles/endpoints/customdomains?pivots=deployment-language-arm-template"
}