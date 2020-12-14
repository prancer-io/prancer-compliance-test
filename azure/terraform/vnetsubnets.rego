package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_subnet

#
# PR-AZR-0066-TRF
# PR-AZR-0067-TRF
#

default vnet_subnet_nsg = null

azure_attribute_absence["vnet_subnet_nsg"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_subnet"
    count([c | input.json.resources[_].type == "azurerm_subnet_network_security_group_association";
    	   c := 1]) == 0
}

azure_issue["vnet_subnet_nsg"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_subnet"
    count([c | r := input.json.resources[_];
               r.type == "azurerm_subnet_network_security_group_association";
               re_match(concat("", ["^.*\\.", resource.name, "\\..*$"]), r.properties.subnet_id);
               c := 1]) == 0
    true == false # workaround for inconsistent resource naming
}

vnet_subnet_nsg {
    lower(input.json.resources[_].type) == "azurerm_subnet"
    not azure_issue["vnet_subnet_nsg"]
    not azure_attribute_absence["vnet_subnet_nsg"]
}

vnet_subnet_nsg = false {
    azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg = false {
    azure_attribute_absence["vnet_subnet_nsg"]
}

vnet_subnet_nsg_err = "Azure Virtual Network subnet is not configured with a Network Security Group" {
    azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg_miss_err = "Azure Virtual Network subnet is not configured with a Network Security Group" {
    azure_attribute_absence["vnet_subnet_nsg"]
}
