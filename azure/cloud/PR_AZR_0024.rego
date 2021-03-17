#
# PR-AZR-0024
#

package rule
default rulepass = true

# Azure Network Security Group (NSG) having Inbound rule overly permissive to all traffic from Internet on TCP protocol
# If NSG dose not having Inbound rule overly permissive to all traffic from Internet on TCP protocol test will pass

# https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/networkSecurityGroups/hardikVM-nsg

rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(security_rule) > 0
}

# "securityRules[?(@.sourceAddressPrefix=='Internet' && @.protocol=='TCP' &&  @.access=='Allow' &&
# )].direction contains Inbound"

security_rule["security_protocol_tcp"] {
    some security_rule
    get_protcol_rule[security_rule]
    security_rule.properties.protocol = "TCP"
}

security_rule["security_protocol_any"] {
    some security_rule
    get_protcol_rule[security_rule]
    security_rule.properties.protocol = "*"
}

get_protcol_rule[security_rule] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.sourceAddressPrefix = "Internet"
    security_rule.properties.access = "Allow"
    security_rule.properties.direction = "Inbound"
}