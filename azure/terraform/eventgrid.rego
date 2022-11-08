package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventgrid_topic
#
# PR-AZR-TRF-EGR-001
#

default event_grid_topic_has_public_network_access_disabled = null
# By default it is true.
azure_attribute_absence["event_grid_topic_has_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventgrid_topic"
    not has_property(resource.properties, "public_network_access_enabled")
}

azure_issue["event_grid_topic_has_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventgrid_topic"
    resource.properties.public_network_access_enabled == true
}

event_grid_topic_has_public_network_access_disabled {
    lower(input.resources[_].type) == "azurerm_eventgrid_topic"
    not azure_attribute_absence["event_grid_topic_has_public_network_access_disabled"]
    not azure_issue["event_grid_topic_has_public_network_access_disabled"]
}

event_grid_topic_has_public_network_access_disabled = false {
    azure_attribute_absence["event_grid_topic_has_public_network_access_disabled"]
}

event_grid_topic_has_public_network_access_disabled = false {
    azure_issue["event_grid_topic_has_public_network_access_disabled"]
}

event_grid_topic_has_public_network_access_disabled_err = "azurerm_eventgrid_topic resoruce property public_network_access_enabled is missing" {
    azure_attribute_absence["event_grid_topic_has_public_network_access_disabled"]
} else = "Azure Event Grid topics public network access is currently not disabled" {
    azure_issue["event_grid_topic_has_public_network_access_disabled"]
}

event_grid_topic_has_public_network_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-EGR-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Event Grid topics should disable public network access",
    "Policy Description": "Disabling public network access improves security by ensuring that the resource isn't exposed on the public internet. You can limit exposure of your resources by creating private endpoints instead. Learn more at: https://aka.ms/privateendpoints.",
    "Resource Type": "azurerm_eventgrid_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventgrid_topic"
}


#
# PR-AZR-TRF-EGR-002
#

default event_grid_topic_has_local_auth_disabled = null
# Default value is true
azure_attribute_absence["event_grid_topic_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventgrid_topic"
    not has_property(resource.properties, "local_auth_enabled")
}

azure_issue["event_grid_topic_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventgrid_topic"
    resource.properties.local_auth_enabled == true
}

event_grid_topic_has_local_auth_disabled {
    lower(input.resources[_].type) == "azurerm_eventgrid_topic"
    not azure_attribute_absence["event_grid_topic_has_local_auth_disabled"]
    not azure_issue["event_grid_topic_has_local_auth_disabled"]
}

event_grid_topic_has_local_auth_disabled = false {
    azure_attribute_absence["event_grid_topic_has_local_auth_disabled"]
}

event_grid_topic_has_local_auth_disabled = false {
    azure_issue["event_grid_topic_has_local_auth_disabled"]
}

event_grid_topic_has_local_auth_disabled_err = "azurerm_eventgrid_topic resoruce property local_auth_enabled is missing" {
    azure_attribute_absence["event_grid_topic_has_local_auth_disabled"]
} else = "Azure Event Grid topics local authentication is currently not disabled" {
    azure_issue["event_grid_topic_has_local_auth_disabled"]
}

event_grid_topic_has_local_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-EGR-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Event Grid topics should disable local authentication",
    "Policy Description": "Disable local authentication methods so that your Azure Event Grid topics exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/aeg-disablelocalauth.",
    "Resource Type": "azurerm_eventgrid_topic",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventgrid_topic"
}


#
# PR-AZR-TRF-EGR-005
#

default event_grid_domain_has_public_network_access_disabled = null
# By default it is true
azure_attribute_absence["event_grid_domain_has_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventgrid_domain"
    not has_property(resource.properties, "public_network_access_enabled")
}

azure_issue["event_grid_domain_has_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventgrid_domain"
    resource.properties.public_network_access_enabled == true
}

event_grid_domain_has_public_network_access_disabled {
    lower(input.resources[_].type) == "azurerm_eventgrid_domain"
    not azure_attribute_absence["event_grid_domain_has_public_network_access_disabled"]
    not azure_issue["event_grid_domain_has_public_network_access_disabled"]
}

event_grid_domain_has_public_network_access_disabled = false {
    azure_attribute_absence["event_grid_domain_has_public_network_access_disabled"]
}

event_grid_domain_has_public_network_access_disabled = false {
    azure_issue["event_grid_domain_has_public_network_access_disabled"]
}

event_grid_domain_has_public_network_access_disabled_err = "azurerm_eventgrid_domain resoruce property public_network_access_enabled is missing" {
    azure_attribute_absence["event_grid_domain_has_public_network_access_disabled"]
} else = "Azure Event Grid domains public network access is currently not disabled" {
    azure_issue["event_grid_domain_has_public_network_access_disabled"]
}

event_grid_domain_has_public_network_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-EGR-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Event Grid domains should disable public network access",
    "Policy Description": "Disable public network access for Azure Event Grid resource so that it isn't accessible over the public internet. This will help protect them against data leakage risks. You can limit exposure of your resources by creating private endpoints instead. Learn more at: https://aka.ms/privateendpoints.",
    "Resource Type": "azurerm_eventgrid_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventgrid_domain"
}


#
# PR-AZR-TRF-EGR-006
#

default event_grid_domain_has_local_auth_disabled = null
# Default value is true
azure_attribute_absence["event_grid_domain_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventgrid_domain"
    not has_property(resource.properties, "local_auth_enabled")
}

azure_issue["event_grid_domain_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventgrid_domain"
    resource.properties.local_auth_enabled == true
}

event_grid_domain_has_local_auth_disabled {
    lower(input.resources[_].type) == "azurerm_eventgrid_domain"
    not azure_attribute_absence["event_grid_domain_has_local_auth_disabled"]
    not azure_issue["event_grid_domain_has_local_auth_disabled"]
}

event_grid_domain_has_local_auth_disabled = false {
    azure_attribute_absence["event_grid_domain_has_local_auth_disabled"]
}

event_grid_domain_has_local_auth_disabled = false {
    azure_issue["event_grid_domain_has_local_auth_disabled"]
}

event_grid_domain_has_local_auth_disabled_err = "azurerm_eventgrid_domain resoruce property local_auth_enabled is missing" {
    azure_attribute_absence["event_grid_domain_has_local_auth_disabled"]
} else = "Azure Event Grid domains local authentication is currently not disabled" {
    azure_issue["event_grid_domain_has_local_auth_disabled"]
}

event_grid_domain_has_local_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-EGR-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Event Grid domains should disable local authentication",
    "Policy Description": "Disable local authentication methods so that your Azure Event Grid domains exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/aeg-disablelocalauth.",
    "Resource Type": "azurerm_eventgrid_domain",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventgrid_domain"
}