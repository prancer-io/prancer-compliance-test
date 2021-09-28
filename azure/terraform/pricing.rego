package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_security_center_subscription_pricing
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-0091-TRF
#

default pricing = null

azure_attribute_absence["pricing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    not resource.properties.tier
}

azure_issue["pricing"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_security_center_subscription_pricing"
    lower(resource.properties.tier) != "standard"
}

pricing {
    lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
    not azure_attribute_absence["pricing"]
    not azure_issue["pricing"]
}

pricing = false {
    azure_attribute_absence["pricing"]
}

pricing = false {
    azure_issue["pricing"]
}

pricing_err = "azurerm_security_center_subscription_pricing property 'tier' need to be exist. Its missing from the resource. Please set the value to 'standard' after property addition." {
    azure_attribute_absence["pricing"]
} else = "Azure Security Center currently dont have 'standard' pricing tier configured" {
    azure_issue["pricing"]
}

pricing_metadata := {
    "Policy Code": "PR-AZR-0091-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Security Center should have pricing tier configured to 'standard'",
    "Policy Description": "Selecting the standard pricing tier will enable threat detection for networks and virtual systems by providing threat intelligence, anomaly detection, and behavior analytics in Azure Security Center.",
    "Resource Type": "azurerm_security_center_subscription_pricing",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-0060-TRF
#

#default security_center_azure_defender_is_on_for_servers = null

#azure_attribute_absence["security_center_azure_defender_is_on_for_servers"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_security_center_subscription_pricing"
#    not resource.properties.tier
#}

#azure_attribute_absence["security_center_azure_defender_is_on_for_servers"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_security_center_subscription_pricing"
#    not resource.properties.resource_type
#}

#no_azure_issue["security_center_azure_defender_is_on_for_servers"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_security_center_subscription_pricing"
#    lower(resource.properties.tier) == "standard"
#}

#no_azure_issue["security_center_azure_defender_is_on_for_servers"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_security_center_subscription_pricing"
#    lower(resource.properties.resource_type) != "virtualmachines"
#}

#security_center_azure_defender_is_on_for_servers {
#    lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
#    not azure_attribute_absence["security_center_azure_defender_is_on_for_servers"]
#    no_azure_issue["security_center_azure_defender_is_on_for_servers"]
#}

#security_center_azure_defender_is_on_for_servers = false {
#    azure_attribute_absence["security_center_azure_defender_is_on_for_servers"]
#}

#security_center_azure_defender_is_on_for_servers = false {
#    not no_azure_issue["security_center_azure_defender_is_on_for_servers"]
#}

#security_center_azure_defender_is_on_for_servers_err = "azurerm_security_center_subscription_pricing property 'tier' and 'resource_type' both need to be exist. one or both are missing from the resource. Please either set tier = 'standard' or dont set 'VirtualMachines' as resource_type after property addition." {
#    azure_attribute_absence["security_center_azure_defender_is_on_for_servers"]
#} else = "Azure Security Center Defender is currently not enabled for Servers" {
#    not no_azure_issue["security_center_azure_defender_is_on_for_servers"]
#}

#security_center_azure_defender_is_on_for_servers_metadata := {
#    "Policy Code": "PR-AZR-0060-TRF",
#    "Type": "IaC",
#    "Product": "AZR",
#    "Language": "Terraform",
#    "Policy Title": "Azure Security Center Defender should be enabled for Servers",
#    "Policy Description": "Azure Defender provides security alerts and advanced threat protection for virtual machines, SQL databases, containers, web applications, your network, and more.",
#    "Resource Type": "azurerm_security_center_subscription_pricing",
#    "Policy Help URL": "",
#    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
#}
