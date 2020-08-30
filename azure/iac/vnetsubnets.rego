package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets

#
# Azure Virtual Network subnet is not configured with a Network Security Group (275)
# Azure Virtual Network subnet is not configured with a Network Security Group TJX (276)
#

default vnet_subnet_nsg = null

azure_issue["vnet_subnet_nsg"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/virtualnetworks/subnets"
    count([c | resource.properties.networkSecurityGroup.id; c := 1]) == 0
}

vnet_subnet_nsg {
    lower(input.resources[_].type) == "microsoft.network/virtualnetworks/subnets"
    not azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg = false {
    azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg_err = "Azure Virtual Network subnet is not configured with a Network Security Group" {
    azure_issue["vnet_subnet_nsg"]
}
