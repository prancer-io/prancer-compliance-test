package rule
default rulepass = false

# Azure Application Gateway does not have the Web application firewall (WAF) enabled
# If Web application firewall (WAF) enabled test case will pass

# https://docs.microsoft.com/en-us/rest/api/application-gateway/applicationgateways/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/applicationGateways/hardikApplicationGateway

rulepass = true {
   count(ApplicationGateway) == 2
}

#  ['properties.webApplicationFirewallConfiguration'] exist or 
#  ['properties.webApplicationFirewallConfiguration'].enabled is true

ApplicationGateway["firewallMode_enabled"] {
   input.properties.webApplicationFirewallConfiguration
}

ApplicationGateway["firewallMode_enabled_true"] {
   input.properties.webApplicationFirewallConfiguration.enabled = true
}