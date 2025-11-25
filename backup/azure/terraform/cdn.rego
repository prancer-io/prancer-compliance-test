package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_endpoint_custom_domain
#
# PR-AZR-TRF-CDN-001
#

default cdn_customdomain_configured_with_https = null

azure_attribute_absence["cdn_customdomain_configured_with_https"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cdn_endpoint_custom_domain"
    not resource.properties.cdn_managed_https
    not resource.properties.user_managed_https
}

cdn_customdomain_configured_with_https {
    lower(input.resources[_].type) == "azurerm_cdn_endpoint_custom_domain"
    not azure_attribute_absence["cdn_customdomain_configured_with_https"]
}

cdn_customdomain_configured_with_https = false {
    azure_attribute_absence["cdn_customdomain_configured_with_https"]
}

cdn_customdomain_configured_with_https_err = "Azure CDN endpoint block cdn_managed_https or user_managed_https is missing from the resource" {
    azure_attribute_absence["cdn_customdomain_configured_with_https"]
}

cdn_customdomain_configured_with_https_metadata := {
    "Policy Code": "PR-AZR-TRF-CDN-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure CDN Endpoint Custom domains should be configured with HTTPS",
    "Policy Description": "This policy identifies Azure CDN Endpoint Custom domains which has not configured with HTTPS. Enabling HTTPS would allow sensitive data to be delivered securely via TLS/SSL encryption when it is sent across the internet. It is recommended to enable HTTPS in Azure CDN Endpoint Custom domains which will provide additional security and protects your web applications from attacks.",
    "Resource Type": "azurerm_cdn_endpoint_custom_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_endpoint_custom_domain"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_endpoint_custom_domain
#
# PR-AZR-TRF-CDN-002
#

default cdn_customdomain_configured_with_secure_tls = null

azure_attribute_absence["cdn_customdomain_configured_with_secure_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cdn_endpoint_custom_domain"
    not resource.properties.cdn_managed_https
    not resource.properties.user_managed_https
}

azure_attribute_absence["cdn_customdomain_configured_with_secure_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cdn_endpoint_custom_domain"
    not resource.properties.cdn_managed_https[_].tls_version
    not resource.properties.user_managed_https[_].tls_version
}

azure_issue["cdn_customdomain_configured_with_secure_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cdn_endpoint_custom_domain"
    lower(resource.properties.cdn_managed_https[_].tls_version) != "tls12"
    lower(resource.properties.user_managed_https[_].tls_version) != "tls12"
}

cdn_customdomain_configured_with_secure_tls {
    lower(input.resources[_].type) == "azurerm_cdn_endpoint_custom_domain"
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
} else = "Azure CDN endpoint attribute cdn_managed_https.tls_version or user_managed_https.tls_version is missing from the resource" {
    azure_attribute_absence["cdn_customdomain_configured_with_secure_tls"]
}

cdn_customdomain_configured_with_secure_tls_metadata := {
    "Policy Code": "PR-AZR-TRF-CDN-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure CDN Endpoint Custom domains should use secure TLS version",
    "Policy Description": "This policy identifies Azure CDN Endpoint Custom domains which has insecure TLS version. TLS 1.2 resolves the security gap from its preceding versions. As a best security practice, use TLS 1.2 as the minimum TLS version for Azure CDN Endpoint Custom domains.",
    "Resource Type": "microsoft.cdn/profiles/endpoints/customdomains",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_endpoint_custom_domain"
}