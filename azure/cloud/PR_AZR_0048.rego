#
# PR-AZR-0048
#

package rule
default rulepass = true

# Azure Network Security Group with Outbound rule to allow all traffic to any source
# If NSG with Outbound rule to dose not allow all traffic to any source

# https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/networkSecurityGroups/hardikVM-nsg

rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(get_outbound) > 0
}
# "securityRules[?(@.sourceAddressPrefix=='*' &&  @.access=='Allow' && @.destinationAddressPrefix=='*')]
# .direction contains Outbound"

get_outbound["allow_all_traffic_to_any_source"] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.access = "Allow"
    security_rule.properties.direction = "Outbound"
    security_rule.properties.sourceAddressPrefix = "*"
}
get_outbound["allow_all_traffic_to_any_destintion"] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.access = "Allow"
    security_rule.properties.direction = "Outbound"
    security_rule.properties.destinationAddressPrefix = "*"
}