package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways

#
# PR-AZR-0011-ARM
#

default gw_tls = null

azure_attribute_absence["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.sslPolicy.minProtocolVersion
}

azure_issue["gw_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    lower(resource.properties.sslPolicy.minProtocolVersion) != "tlsv1_2"
    lower(resource.properties.sslPolicy.minProtocolVersion) != "tlsv1_3"
}

gw_tls {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
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

gw_tls_miss_err = "App gateway attribute webApplicationFirewallConfiguration missing in the resource" {
    azure_attribute_absence["gw_tls"]
}

#
# PR-AZR-0012-ARM
#

default gw_waf = null

azure_attribute_absence["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    not resource.properties.webApplicationFirewallConfiguration.enabled
}

azure_issue["gw_waf"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/applicationgateways"
    resource.properties.webApplicationFirewallConfiguration.enabled != true
}

gw_waf {
    lower(input.resources[_].type) == "microsoft.network/applicationgateways"
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

gw_waf_miss_err = "App gateway attribute webApplicationFirewallConfiguration missing in the resource" {
    azure_attribute_absence["gw_waf"]
}
