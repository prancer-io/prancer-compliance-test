#
# PR-AZR-0028
#

package rule
default rulepass = true

# Azure Network Security Group (NSG) having Inbound rule overly permissive to allow all traffic from any source to any destiation(TJX)
# If NSG dose not having Inbound rule overly permissive to allow all traffic from any source to any destiation test will pass

# https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get
# https://resources.azure.com/subscriptions/db3667b7-cef9-4523-8e45-e2d9ed4518ab/resourceGroups/hardikResourceGroup/providers/Microsoft.Network/networkSecurityGroups/hardikVM-nsg

rulepass = false {
    lower(input.type) == "microsoft.network/networksecuritygroups"
    count(public_security_rules) > 0
}

metadata := {
    "Policy Code": "PR-AZR-0028",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Network Security Group (NSG) having Inbound rule overly permissive to allow all traffic from any source to any destination (TJX)",
    "Policy Description": "This policy identifies NSGs which allows incoming traffic from any source. A network security group contains a list of security rules that allow or deny inbound or outbound network traffic based on source or destination IP address, port, and protocol. As a best practice, it is recommended to configure NSGs to restrict traffic from known sources on authorized protocols and ports.",
    "Compliance": [],
    "Resource Type": "microsoft.network/networksecuritygroups",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/virtualnetwork/networksecuritygroups/get"
}

# securityRules[?(@.sourceAddressPrefix=='*' && @.destinationPortRange=="*" && @.sourcePortRange==*
# &&  @.access=='Allow' &&  @.destinationAddressPrefix=='*')].direction contains Inbound"

get_security_rule[security_rule] {
    security_rule := input.properties.securityRules[_]
    security_rule.properties.sourceAddressPrefix = "*"
    security_rule.properties.access = "Allow"
    security_rule.properties.destinationAddressPrefix = "*"
    security_rule.properties.direction = "Inbound"
}

public_security_rules["source_port"] {
    some security_rule
    get_security_rule[security_rule]
    security_rule.properties.sourcePortRange = "*"
}
public_security_rules["destination_port"] {
    some security_rule
    get_security_rule[security_rule]
    security_rule.properties.destinationPortRange = "*"
}