#
# PR-AZR-0067
#

package rule

default rulepass = false

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets

rulepass {
    lower(input.type) == "microsoft.network/virtualnetworks/subnets"
    input.properties.networkSecurityGroup.id
}

metadata := {
    "Policy Code": "PR-AZR-0067",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "Cloud",
    "Policy Title": "Azure Virtual Network subnet is not configured with a Network Security Group (TJX)",
    "Policy Description": "** MODIFICATION OF DEFAULT RULE - GatewaySubnets Excluded as of 08 APR 2019, GatewaySubnets do not support the application of NSGs **_x005F_x000D_ _x005F_x000D_ ** AzureFirewallSubnet Excluded as of 08 APR 2019 **_x005F_x000D_  _x005F_x000D_ This policy identifies Azure Virtual Network (VNet) subnets that are not associated with a Network Security Group (NSG). While binding an NSG to a network interface of a Virtual Machine (VM) enables fine-grained control to the VM, associating a NSG to a subnet enables better control over network traffic to all resources within a subnet. As a best practice, associate an NSG with a subnet so that you can protect your VMs on a subnet-level._x005F_x000D_ _x005F_x000D_ For more information, see https://blogs.msdn.microsoft.com/igorpag/2016/05/14/azure-network-security-groups-nsg-best-practices-and-lessons-learned/",
    "Compliance": [],
    "Resource Type": "microsoft.network/virtualnetworks/subnets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets"
}
