package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_application_gateway

#
# PR-AZR-0011-TRF
#

default gw_tls = null

azure_attribute_absence["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    resource.properties.ssl_policy != null
    not resource.properties.ssl_policy[_].min_protocol_version
}

azure_issue["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    resource.properties.ssl_policy != null
    lower(resource.properties.ssl_policy[_].min_protocol_version) != "tlsv1_2"
    lower(resource.properties.ssl_policy[_].min_protocol_version) != "tlsv1_3"
}

gw_tls {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_issue["gw_tls"]
    not azure_attribute_absence["gw_tls"]
}

gw_tls = false {
    azure_issue["gw_tls"]
}

gw_tls = false {
    azure_attribute_absence["gw_tls"]
}

gw_tls_err = "Azure Application Gateway allows TLSv1.1 or lower" {
    azure_issue["gw_tls"]
}

gw_tls_miss_err = "App gateway attribute min_protocol_version missing in the resource" {
    azure_attribute_absence["gw_tls"]
}

gw_tls_metadata := {
    "Policy Code": "PR-AZR-0011-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Application Gateway allows TLSv1.1 or lower",
    "Policy Description": "The Application Gateway supports end-to-end SSL encryption using multiple TLS versions and by default, it supports TLS version 1.0 as the minimum version._x005F_x000D_ _x005F_x000D_ This policy identifies the Application Gateway instances that are configured to use TLS versions 1.1 or lower as the minimum protocol version. As a best practice set the MinProtocolVersion to TLSv1.2 (if you use custom SSL policy) or use the predefined â€˜AppGwSslPolicy20170401Sâ€™ policy.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_application_gateway"
}

#
# PR-AZR-0012-TRF
#

default gw_waf = null

azure_attribute_absence["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    resource.properties.waf_configuration != null
    not resource.properties.waf_configuration[_].enabled
}

azure_issue["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    resource.properties.waf_configuration != null
    resource.properties.waf_configuration[_].enabled != true
}

gw_waf {
    lower(input.resources[_].type) == "azurerm_application_gateway"
    not azure_issue["gw_waf"]
    not azure_attribute_absence["gw_waf"]
}

gw_waf = false {
    azure_issue["gw_waf"]
}

gw_waf = false {
    azure_attribute_absence["gw_waf"]
}

gw_waf_err = "Azure Application Gateway does not have the WAF enabled" {
    azure_issue["gw_waf"]
}

gw_waf_miss_err = "App gateway attribute waf_configuration missing in the resource" {
    azure_attribute_absence["gw_waf"]
}

gw_waf_metadata := {
    "Policy Code": "PR-AZR-0012-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Application Gateway does not have the Web application firewall (WAF) enabled",
    "Policy Description": "This policy identifies Azure Application Gateways that do not have Web application firewall (WAF) enabled. As a best practice, enable WAF to manage and protect your web applications behind the Application Gateway from common exploits and vulnerabilities.",
    "Resource Type": "azurerm_application_gateway",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/azurerm_application_gateway"
}
