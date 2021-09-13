package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.databricks/workspaces?tabs=json

#
# PR-AZR-0117-ARM
#

default databrics_workspace_has_public_ip_disabled = null

azure_attribute_absence["databrics_workspace_has_public_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.databricks/workspaces"
    not resource.properties.parameters.enableNoPublicIp.value
}

azure_issue["databrics_workspace_has_public_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.databricks/workspaces"
    resource.properties.parameters.enableNoPublicIp.value != true
}

databrics_workspace_has_public_ip_disabled {
    lower(input.resources[_].type) == "microsoft.databricks/workspaces"
    not azure_attribute_absence["databrics_workspace_has_public_ip_disabled"]
    not azure_issue["databrics_workspace_has_public_ip_disabled"]
}

databrics_workspace_has_public_ip_disabled = false {
    azure_attribute_absence["databrics_workspace_has_public_ip_disabled"]
}

databrics_workspace_has_public_ip_disabled = false {
    azure_issue["databrics_workspace_has_public_ip_disabled"]
}

databrics_workspace_has_public_ip_disabled_err = "Azure Databricks currenty does not have public ip disabled" {
    azure_issue["databrics_workspace_has_public_ip_disabled"]
} else = "Microsoft.Databricks/workspaces property 'parameters.enableNoPublicIp' is missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["databrics_workspace_has_public_ip_disabled"]
}

databrics_workspace_has_public_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-0117-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Databricks shoud not use public IP address",
    "Policy Description": "Azure Databricks is a data analytics platform optimized for the Microsoft Azure cloud services platform. This policy will identify Databricks which does not have public ip disabled and warn.",
    "Resource Type": "Microsoft.Databricks/workspaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.databricks/workspaces?tabs=json"
}


#
# PR-AZR-0118-ARM
#

default databrics_workspace_has_vnet_integration = null

azure_attribute_absence["databrics_workspace_has_vnet_integration"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.databricks/workspaces"
    not resource.properties.parameters.customVirtualNetworkId
}

azure_issue["databrics_workspace_has_vnet_integration"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.databricks/workspaces"
    contains(lower(resource.properties.parameters.customVirtualNetworkId), "microsoft.network/virtualnetworks") != true
}

databrics_workspace_has_vnet_integration {
    lower(input.resources[_].type) == "microsoft.databricks/workspaces"
    not azure_attribute_absence["databrics_workspace_has_vnet_integration"]
    not azure_issue["databrics_workspace_has_vnet_integration"]
}

databrics_workspace_has_vnet_integration = false {
    azure_attribute_absence["databrics_workspace_has_vnet_integration"]
}

databrics_workspace_has_vnet_integration = false {
    azure_issue["databrics_workspace_has_vnet_integration"]
}

databrics_workspace_has_vnet_integration_err = "Azure Databricks currenty does not have any vnet integration" {
    azure_issue["databrics_workspace_has_vnet_integration"]
} else = "Microsoft.Databricks/workspaces property 'parameters.customVirtualNetworkId' is missing from the resource. Please set vnet id as the value after property addition." {
    azure_attribute_absence["databrics_workspace_has_vnet_integration"]
}

databrics_workspace_has_vnet_integration_metadata := {
    "Policy Code": "PR-AZR-0118-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Databricks should have vnet integration",
    "Policy Description": "Azure Databricks is a data analytics platform optimized for the Microsoft Azure cloud services platform. This policy will identify Databricks which does not have vnet integration and warn.",
    "Resource Type": "Microsoft.Databricks/workspaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.databricks/workspaces?tabs=json"
}
