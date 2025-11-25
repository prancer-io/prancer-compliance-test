package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/synapse_workspace
# PR-AZR-TRF-SWM-001
#

default synapse_workspace_enables_managed_virtual_network = null
#Defaults to false
azure_attribute_absence["synapse_workspace_enables_managed_virtual_network"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_synapse_workspace"
    not resource.properties.managed_virtual_network_enabled
}

azure_issue["synapse_workspace_enables_managed_virtual_network"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_synapse_workspace"
    resource.properties.managed_virtual_network_enabled != true
}

synapse_workspace_enables_managed_virtual_network {
    lower(input.resources[_].type) == "azurerm_synapse_workspace"
    not azure_attribute_absence["synapse_workspace_enables_managed_virtual_network"]
    not azure_issue["synapse_workspace_enables_managed_virtual_network"]
}

synapse_workspace_enables_managed_virtual_network = false {
    azure_attribute_absence["synapse_workspace_enables_managed_virtual_network"]
}

synapse_workspace_enables_managed_virtual_network = false {
    azure_issue["synapse_workspace_enables_managed_virtual_network"]
}

synapse_workspace_enables_managed_virtual_network_err = "azurerm_synapse_workspace property 'managed_virtual_network_enabled' is missing from the resource" {
    azure_attribute_absence["synapse_workspace_enables_managed_virtual_network"]
} else = "Managed workspace virtual network on Azure Synapse workspaces is currently not enabled" {
    azure_issue["synapse_workspace_enables_managed_virtual_network"]
}

synapse_workspace_enables_managed_virtual_network_metadata := {
    "Policy Code": "PR-AZR-TRF-SWM-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Managed workspace virtual network on Azure Synapse workspaces should be enabled",
    "Policy Description": "Enabling a managed workspace virtual network ensures that your workspace is network isolated from other workspaces. Data integration and Spark resources deployed in this virtual network also provides user level isolation for Spark activities.",
    "Resource Type": "azurerm_synapse_workspace",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/synapse_workspace"
}