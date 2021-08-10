package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/databricks_workspace

#
# PR-AZR-0117-TRF
#

default databrics_workspace_has_public_ip_disabled = null

azure_attribute_absence["databrics_workspace_has_public_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_databricks_workspace"
    not resource.properties.custom_parameters
}

azure_attribute_absence["databrics_workspace_has_public_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_databricks_workspace"
    custom_parameters := resource.properties.custom_parameters[_]
    not custom_parameters.no_public_ip
}

azure_issue["databrics_workspace_has_public_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_databricks_workspace"
    custom_parameters := resource.properties.custom_parameters[_]
    custom_parameters.no_public_ip != true
}

databrics_workspace_has_public_ip_disabled {
    lower(input.resources[_].type) == "azurerm_databricks_workspace"
    not azure_attribute_absence["databrics_workspace_has_public_ip_disabled"]
    not azure_issue["databrics_workspace_has_public_ip_disabled"]
}

databrics_workspace_has_public_ip_disabled = false {
    azure_attribute_absence["databrics_workspace_has_public_ip_disabled"]
}

databrics_workspace_has_public_ip_disabled = false {
    azure_issue["databrics_workspace_has_public_ip_disabled"]
}

databrics_workspace_has_public_ip_disabled_err = "azurerm_databricks_workspace property 'custom_parameters.no_public_ip' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["databrics_workspace_has_public_ip_disabled"]
} else = "Azure Databricks currenty does not have public ip disabled" {
    azure_issue["databrics_workspace_has_public_ip_disabled"]
}

databrics_workspace_has_public_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-0117-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Databricks shoud not use public IP address",
    "Policy Description": "Azure Databricks is a data analytics platform optimized for the Microsoft Azure cloud services platform. This policy will identify Databricks which does not have public ip disabled and warn.",
    "Resource Type": "azurerm_databricks_workspace",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/databricks_workspace"
}

#
# PR-AZR-0118-TRF
#

default databrics_workspace_has_vnet_integration = null

azure_attribute_absence["databrics_workspace_has_vnet_integration"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_databricks_workspace"
    not resource.properties.custom_parameters
}

azure_attribute_absence["databrics_workspace_has_vnet_integration"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_databricks_workspace"
    custom_parameters := resource.properties.custom_parameters[_]
    not custom_parameters.virtual_network_id
}

azure_issue["databrics_workspace_has_vnet_integration"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_databricks_workspace"
    custom_parameters := resource.properties.custom_parameters[_]
    contains(lower(custom_parameters.virtual_network_id), "microsoft.network/virtualnetworks") != true
}

databrics_workspace_has_vnet_integration {
    lower(input.resources[_].type) == "azurerm_databricks_workspace"
    not azure_attribute_absence["databrics_workspace_has_vnet_integration"]
    not azure_issue["databrics_workspace_has_vnet_integration"]
}

databrics_workspace_has_vnet_integration = false {
    azure_attribute_absence["databrics_workspace_has_vnet_integration"]
}

databrics_workspace_has_vnet_integration = false {
    azure_issue["databrics_workspace_has_vnet_integration"]
}

databrics_workspace_has_vnet_integration_err = "azurerm_databricks_workspace property 'custom_parameters.virtual_network_id' is missing from the resource. Please set vnet id as the value after property addition." {
    azure_attribute_absence["databrics_workspace_has_vnet_integration"]
} else = "Azure Databricks currenty does not have any vnet integration" {
    azure_issue["databrics_workspace_has_vnet_integration"]
}

databrics_workspace_has_vnet_integration_metadata := {
    "Policy Code": "PR-AZR-0118-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Databricks should have vnet integration",
    "Policy Description": "Azure Databricks is a data analytics platform optimized for the Microsoft Azure cloud services platform. This policy will identify Databricks which does not have vnet integration and warn.",
    "Resource Type": "azurerm_databricks_workspace",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/databricks_workspace"
}