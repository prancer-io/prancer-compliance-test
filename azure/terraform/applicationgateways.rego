package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_application_gateway

#
# PR-AZR-0011-TRF
#

default gw_tls = null

azure_attribute_absence["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.ssl_policy.min_protocol_version
}

azure_issue["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    lower(resource.properties.ssl_policy.min_protocol_version) != "tlsv1_2"
    lower(resource.properties.ssl_policy.min_protocol_version) != "tlsv1_3"
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

#
# PR-AZR-0012-TRF
#

default gw_waf = null

azure_attribute_absence["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    not resource.properties.waf_configuration.enabled
}

azure_issue["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_application_gateway"
    resource.properties.waf_configuration.enabled != true
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
