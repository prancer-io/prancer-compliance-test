#
# PR-AZR-0012
#

package rule
default rulepass = false

# Azure Application Gateway does not have the Web application firewall (WAF) enabled
# If Web application firewall (WAF) enabled test case will pass

# https://docs.microsoft.com/en-us/rest/api/application-gateway/applicationgateways/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/applicationGateways/hardikApplicationGateway

rulepass {
    lower(input.type) == "microsoft.network/applicationgateways"
    input.properties.webApplicationFirewallConfiguration.enabled == true
}

metadata := {
    "Policy Code": "PR-AZR-0012",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Application Gateway does not have the Web application firewall (WAF) enabled",
    "Policy Description": "This policy identifies Azure Application Gateways that do not have Web application firewall (WAF) enabled. As a best practice, enable WAF to manage and protect your web applications behind the Application Gateway from common exploits and vulnerabilities.",
    "Resource Type": "microsoft.network/applicationgateways",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/application-gateway/applicationgateways/get"
}
