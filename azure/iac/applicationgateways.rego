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

gw_tls_err = "App gateway attribute webApplicationFirewallConfiguration missing in the resource" {
    azure_attribute_absence["gw_tls"]
}

gw_tls_metadata := {
    "Policy Code": "PR-AZR-0011-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Application Gateway allows TLSv1.1 or lower",
    "Policy Description": "The Application Gateway supports end-to-end SSL encryption using multiple TLS versions and by default, it supports TLS version 1.0 as the minimum version._x005F_x000D_ _x005F_x000D_ This policy identifies the Application Gateway instances that are configured to use TLS versions 1.1 or lower as the minimum protocol version. As a best practice set the MinProtocolVersion to TLSv1.2 (if you use custom SSL policy) or use the predefined â€˜AppGwSslPolicy20170401Sâ€™ policy.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
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

gw_waf_err = "App gateway attribute webApplicationFirewallConfiguration missing in the resource" {
    azure_attribute_absence["gw_waf"]
}

gw_waf_metadata := {
    "Policy Code": "PR-AZR-0012-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Application Gateway does not have the Web application firewall (WAF) enabled",
    "Policy Description": "This policy identifies Azure Application Gateways that do not have Web application firewall (WAF) enabled. As a best practice, enable WAF to manage and protect your web applications behind the Application Gateway from common exploits and vulnerabilities.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/applicationgateways"
}
