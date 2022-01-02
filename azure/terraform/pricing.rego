package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_security_center_subscription_pricing
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing
#
# PR-AZR-TRF-ASC-001
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
    "Policy Code": "PR-AZR-TRF-ASC-001",
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
# PR-AZR-TRF-ASC-006

# default msdefender_for_cloud_is_enabled_for_servers = null

# # Defaults to VirtualMachines.
# azure_resource_type_attribute_absence ["msdefender_for_cloud_is_enabled_for_servers"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_security_center_subscription_pricing"
#     not resource.properties.resource_type
# }

# azure_attribute_absence ["msdefender_for_cloud_is_enabled_for_servers"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_security_center_subscription_pricing"
#     not resource.properties.tier    
# }

# azure_issue ["msdefender_for_cloud_is_enabled_for_servers"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_security_center_subscription_pricing"
#     lower(resource.properties.tier) != "standard"
# }

# azure_issue ["msdefender_for_cloud_is_enabled_for_servers"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_security_center_subscription_pricing"
#     lower(resource.properties.resource_type) != "virtualmachines"
# }

# msdefender_for_cloud_is_enabled_for_servers {
#     lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
#     not azure_attribute_absence["msdefender_for_cloud_is_enabled_for_servers"]
#     not azure_issue["msdefender_for_cloud_is_enabled_for_servers"]
# }

# msdefender_for_cloud_is_enabled_for_servers = false {
#     azure_issue["msdefender_for_cloud_is_enabled_for_servers"]
# }

# msdefender_for_cloud_is_enabled_for_servers = false {
#     azure_attribute_absence["msdefender_for_cloud_is_enabled_for_servers"]
# }

# msdefender_for_cloud_is_enabled_for_servers {
# 	lower(input.resources[_].type) == "azurerm_security_center_subscription_pricing"
#     azure_resource_type_attribute_absence["msdefender_for_cloud_is_enabled_for_servers"]
#     not azure_attribute_absence["msdefender_for_cloud_is_enabled_for_servers"]
# }

# msdefender_for_cloud_is_enabled_for_servers_err = "azurerm_security_center_subscription_pricing property 'tier' need to be exist. Its missing from the resource. Please set the value to 'Standard' after property addition." {
#     azure_attribute_absence["msdefender_for_cloud_is_enabled_for_servers"]
# } else = "MS Defender for cloud is currently not enabled for servers" {
#     azure_issue["msdefender_for_cloud_is_enabled_for_servers"]
# }

# msdefender_for_cloud_is_enabled_for_servers_metadata := {
#     "Policy Code": "PR-AZR-TRF-ASC-006",
#     "Type": "IaC",
#     "Product": "AZR",
#     "Language": "Terraform",
#     "Policy Title": "Ensure MS Defender for cloud is enabled for servers",
#     "Policy Description": "This policy will monitor Microsoft Azure defender for cloud and will rails an alert if defender is not enabled for servers",
#     "Resource Type": "azurerm_security_center_subscription_pricing",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing"
# }

