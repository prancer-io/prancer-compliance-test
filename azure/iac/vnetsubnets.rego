package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets

#
# Azure Virtual Network subnet is not configured with a Network Security Group (275)
# Azure Virtual Network subnet is not configured with a Network Security Group TJX (276)
#

default vnet_subnet_nsg = null

vnet_subnet_nsg {
    lower(input.type) == "microsoft.network/virtualnetworks/subnets"
    input.properties.networkSecurityGroup.id
}

vnet_subnet_nsg = false {
    lower(input.type) == "microsoft.network/virtualnetworks/subnets"
    count([c | input.properties.networkSecurityGroup.id; c := 1]) == 0
}

vnet_subnet_nsg_err = "Azure Virtual Network subnet is not configured with a Network Security Group" {
    vnet_subnet_nsg == false
}
