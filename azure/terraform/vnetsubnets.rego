package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_subnet
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet_network_security_group_association
#
# PR-AZR-0066-TRF
#

default vnet_subnet_nsg = null

#azure_attribute_absence["vnet_subnet_nsg"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_subnet"
#    count([c | input.resources[_].type == "azurerm_subnet_network_security_group_association";
#    	   c := 1]) == 0
#}

#azure_issue["vnet_subnet_nsg"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_subnet"
#    count([c | r := input.resources[_];
#               r.type == "azurerm_subnet_network_security_group_association";
#               re_match(concat("", ["^.*\\.", resource.name, "\\..*$"]), r.properties.subnet_id); #matching is not wokring as expected due tf veriable reference in json. eventually we should match with resource.id instead of resource.name as per document but the id will only available from tf output file. it will be impossible to get id during compile time.
#               c := 1]) == 0
#    true == false # workaround for inconsistent resource naming
#}

#azure_issue["vnet_subnet_nsg"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_network_security_group"
#    count([c | r := input.resources[_];
#               r.type == "azurerm_subnet_network_security_group_association";
#               re_match(concat("", ["^.*\\.", resource.name, "\\..*$"]), r.properties.network_security_group_id ); #matching is not wokring as expected due tf veriable reference in json. eventually we should match with resource.id instead of resource.name as per document but the id will only available from tf output file. it will be impossible to get id during compile time.
#               c := 1]) == 0
#    true == false # workaround for inconsistent resource naming
#}

azure_attribute_absence["vnet_subnet_nsg"] {
    count([c | input.resources[_].type == "azurerm_subnet"; c := 1]) != count([c | input.resources[_].type == "azurerm_subnet_network_security_group_association"; c := 1])
}

azure_attribute_absence["vnet_subnet_nsg"] {
    count([c | input.resources[_].type == "azurerm_network_security_group"; c := 1]) != count([c | input.resources[_].type == "azurerm_subnet_network_security_group_association"; c := 1])
}

azure_attribute_absence["vnet_subnet_nsg"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_subnet_network_security_group_association"
    not resource.subnet_id
}

azure_attribute_absence["vnet_subnet_nsg"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_subnet_network_security_group_association"
    not resource.network_security_group_id
}

azure_issue["vnet_subnet_nsg"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_subnet_network_security_group_association"
    count(resource.subnet_id) == 0
}

azure_issue["vnet_subnet_nsg"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_subnet_network_security_group_association"
    count(resource.network_security_group_id) == 0
}

vnet_subnet_nsg {
    lower(input.resources[_].type) == "azurerm_subnet"
    not azure_attribute_absence["vnet_subnet_nsg"]
    not azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg = false {
    azure_attribute_absence["vnet_subnet_nsg"]
}

vnet_subnet_nsg = false {
    azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg_err = "Resource azurerm_subnet, azurerm_network_security_group and azurerm_subnet_network_security_group_association need to be exist and property 'subnet_id' and 'network_security_group_id' both need to be exist under azurerm_subnet_network_security_group_association. one or all are missing from the resource." {
    azure_attribute_absence["vnet_subnet_nsg"]
} else = "Azure Virtual Network subnet is not configured with a Network Security Group" {
    azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg_metadata := {
    "Policy Code": "PR-AZR-0066-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Virtual Network subnet should be configured with Network Security Group",
    "Policy Description": "This policy identifies Azure Virtual Network (VNet) subnets that are not associated with a Network Security Group (NSG). While binding an NSG to a network interface of a Virtual Machine (VM) enables fine-grained control to the VM, associating a NSG to a subnet enables better control over network traffic to all resources within a subnet. As a best practice, associate an NSG with a subnet so that you can protect your VMs on a subnet-level._x005F_x000D_ _x005F_x000D_ For more information, see https://blogs.msdn.microsoft.com/igorpag/2016/05/14/azure-network-security-groups-nsg-best-practices-and-lessons-learned/",
    "Resource Type": "azurerm_subnet",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/subnet_network_security_group_association"
}
