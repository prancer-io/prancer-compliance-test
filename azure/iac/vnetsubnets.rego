package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets

#
# PR-AZR-0066-ARM
#

default vnet_subnet_nsg = null

# id property is optional
#azure_issue["vnet_subnet_nsg"] {
#    resource := input.resources[_]
#    lower(resource.type) == "microsoft.network/virtualnetworks/subnets"
#    count([c | resource.properties.networkSecurityGroup.id; c := 1]) == 0
#}

azure_issue["vnet_peer"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.network/virtualnetworks/subnets"
    not resource.properties.networkSecurityGroup
}

vnet_subnet_nsg {
    lower(input.resources[_].type) == "microsoft.network/virtualnetworks/subnets"
    not azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg = false {
    azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg_err = "Azure Virtual Network subnet is currently not configured with any Network Security Group" {
    azure_issue["vnet_subnet_nsg"]
}

vnet_subnet_nsg_metadata := {
    "Policy Code": "PR-AZR-0066-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Virtual Network subnet should be configured with Network Security Group",
    "Policy Description": "This policy identifies Azure Virtual Network (VNet) subnet which dont have any association with Network Security Group (NSG). While binding an NSG to a network interface of a Virtual Machine (VM) enables fine-grained control to the VM, associating a NSG to a subnet enables better control over network traffic to all resources within a subnet. As a best practice, associate an NSG with a subnet so that you can protect your VMs on a subnet-level.<br><br>For more information, see https://blogs.msdn.microsoft.com/igorpag/2016/05/14/azure-network-security-groups-nsg-best-practices-and-lessons-learned/",
    "Resource Type": "microsoft.network/virtualnetworks/subnets",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.network/virtualnetworks/subnets"
}
