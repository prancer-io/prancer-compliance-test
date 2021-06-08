#
# PR-AZR-0025
#

package rule
default rulepass = true

# Azure Network Security Group (NSG) having Inbound rule overly permissive to all traffic from Internet on UDP protocol
# If NSG dose not having Inbound rule overly permissive to all traffic from Internet on UDP protocol test will pass

# https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/networkSecurityGroups/hardikVM-nsg

rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(security_protocol_udp) > 0
}

metadata := {
    "Policy Code": "PR-AZR-0025",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Network Security Group (NSG) having Inbound rule overly permissive to all traffic from Internet on UDP protocol",
    "Policy Description": "This policy identifies Azure Network Security Groups (NSGs) which are overly permissive to all traffic from Internet on UDP protocol. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources, allowing only authorized protocols and ports.",
    "Compliance": [],
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get"
}

# "securityRules[?(@.sourceAddressPrefix=='Internet' && @.protocol=='UDP' &&  @.access=='Allow' &&
# )].direction contains Inbound"

security_protocol_udp["security_protocol_udp"] {
    some security_rule
    get_protcol_rule[security_rule]
    security_rule.properties.protocol = "UDP"
}

security_protocol_udp["security_protocol_any"] {
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