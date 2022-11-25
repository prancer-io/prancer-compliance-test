package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }


#
# PR-AZR-TRF-EHB-001
#

default event_hub_namespace_has_local_auth_disabled = null
# Default value is true
azure_attribute_absence["event_hub_namespace_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub_namespace"
    not has_property(resource.properties, "local_authentication_enabled")
}

azure_issue["event_hub_namespace_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub_namespace"
    resource.properties.local_authentication_enabled != false
}

event_hub_namespace_has_local_auth_disabled {
    lower(input.resources[_].type) == "azurerm_eventhub_namespace"
    not azure_attribute_absence["event_hub_namespace_has_local_auth_disabled"]
    not azure_issue["event_hub_namespace_has_local_auth_disabled"]
}

event_hub_namespace_has_local_auth_disabled = false {
    azure_attribute_absence["event_hub_namespace_has_local_auth_disabled"]
}

event_hub_namespace_has_local_auth_disabled = false {
    azure_issue["event_hub_namespace_has_local_auth_disabled"]
}

event_hub_namespace_has_local_auth_disabled_err = "azurerm_eventhub_namespace resoruce property local_authentication_enabled is missing" {
    azure_attribute_absence["event_hub_namespace_has_local_auth_disabled"]
} else = "Azure Event Hub namespaces local authentication is currently not disabled" {
    azure_issue["event_hub_namespace_has_local_auth_disabled"]
}

event_hub_namespace_has_local_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-EHB-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Event Hub namespaces should have local authentication methods disabled",
    "Policy Description": "Disabling local authentication methods improves security by ensuring that Azure Event Hub namespaces exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/disablelocalauth-eh.",
    "Resource Type": "azurerm_eventhub_namespace",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventhub_namespace"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventhub_namespace_customer_managed_key
# PR-AZR-TRF-EHB-005

default event_hub_namespace_usage_custom_managed_key_for_encryption = null

azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"] {
    count([c | input.resources[_].type == "azurerm_eventhub_namespace_customer_managed_key"; c := 1]) == 0
}

azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub_namespace_customer_managed_key"
    not resource.properties.eventhub_namespace_id
}

azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub_namespace_customer_managed_key"
    not resource.properties.key_vault_key_ids
}

azure_issue["event_hub_namespace_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub_namespace"
    count([c | r := input.resources[_];
              r.type == "azurerm_eventhub_namespace_customer_managed_key";
              contains(r.properties.eventhub_namespace_id, resource.properties.compiletime_identity);
              r.properties.key_vault_key_ids != "";
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_eventhub_namespace_customer_managed_key";
              contains(r.properties.eventhub_namespace_id, concat(".", [resource.type, resource.name]));
              r.properties.key_vault_key_ids != "";
              c := 1]) == 0
}

event_hub_namespace_usage_custom_managed_key_for_encryption {
    lower(input.resources[_].type) == "azurerm_eventhub_namespace"
    not azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"]
    not azure_issue["event_hub_namespace_usage_custom_managed_key_for_encryption"]
}

event_hub_namespace_usage_custom_managed_key_for_encryption = false {
    lower(input.resources[_].type) == "azurerm_eventhub_namespace"
    azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"]
}

event_hub_namespace_usage_custom_managed_key_for_encryption = false {
    lower(input.resources[_].type) == "azurerm_eventhub_namespace"
    azure_issue["event_hub_namespace_usage_custom_managed_key_for_encryption"]
}

event_hub_namespace_usage_custom_managed_key_for_encryption_err = "Make sure resource azurerm_eventhub_namespace and azurerm_eventhub_namespace_customer_managed_key both exist and property 'eventhub_namespace_id' and 'key_vault_key_ids' exist under azurerm_eventhub_namespace_customer_managed_key. One or both are missing from the resource." {
    lower(input.resources[_].type) == "azurerm_eventhub_namespace"
    azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"]
} else = "Azure Event Hub namespaces currently not using customer-managed key for encryption" {
    lower(input.resources[_].type) == "azurerm_eventhub_namespace"
    azure_issue["mssql_server_alert"]
}

event_hub_namespace_usage_custom_managed_key_for_encryption_metadata := {
    "Policy Code": "PR-AZR-TRF-EHB-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Event Hub namespaces should use customer-managed key for encryption",
    "Policy Description": "Azure Event Hubs supports the option of encrypting data at rest with either Microsoft-managed keys (default) or customer-managed keys. Choosing to encrypt data using customer-managed keys enables you to assign, rotate, disable, and revoke access to the keys that Event Hub will use to encrypt data in your namespace. Note that Event Hub only supports encryption with customer-managed keys for namespaces in dedicated clusters.",
    "Resource Type": "azurerm_eventhub_namespace",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventhub_namespace"
}


#
# PR-AZR-TRF-EHB-006
#

default event_hub_namespace_only_has_rootmanage_sharedaccesskey = null

azure_attribute_absence["event_hub_namespace_only_has_rootmanage_sharedaccesskey"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub_namespace_authorization_rule"
    not resource.properties.name
}

azure_issue["event_hub_namespace_only_has_rootmanage_sharedaccesskey"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub_namespace_authorization_rule"
    lower(resource.properties.name) != "rootmanagesharedaccesskey"
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey {
    lower(input.resources[_].type) == "azurerm_eventhub_namespace_authorization_rule"
    not azure_attribute_absence["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
    not azure_issue["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey = false {
    azure_attribute_absence["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey = false {
    azure_issue["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey_err = "azurerm_eventhub_namespace_authorization_rule resoruce name is missing" {
    azure_attribute_absence["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
} else = "Azure Event Hub namespaces currently dont have RootManageSharedAccessKey as only authorization rules" {
    azure_issue["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey_metadata := {
    "Policy Code": "PR-AZR-TRF-EHB-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "All authorization rules except RootManageSharedAccessKey should be removed from Event Hub namespace",
    "Policy Description": "Event Hub clients should not use a namespace level access policy that provides access to all queues and topics in a namespace. To align with the least privilege security model, you should create access policies at the entity level for queues and topics to provide access to only the specific entity",
    "Resource Type": "azurerm_eventhub_namespace_authorization_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventhub_namespace_authorization_rule"
}



# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventhub_authorization_rule
# PR-AZR-TRF-EHB-007

default event_hub_instance_has_auth_rule_defined = null

azure_attribute_absence["event_hub_instance_has_auth_rule_defined"] {
    count([c | input.resources[_].type == "azurerm_eventhub_authorization_rule"; c := 1]) == 0
}

azure_attribute_absence["event_hub_instance_has_auth_rule_defined"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub_authorization_rule"
    not resource.properties.eventhub_name       
}

azure_issue["event_hub_instance_has_auth_rule_defined"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_eventhub"
    count([c | r := input.resources[_];
              r.type == "azurerm_eventhub_authorization_rule";
              contains(r.properties.eventhub_name, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_eventhub_authorization_rule";
              contains(r.properties.eventhub_name, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
}

event_hub_instance_has_auth_rule_defined {
    lower(input.resources[_].type) == "azurerm_eventhub"
    not azure_attribute_absence["event_hub_instance_has_auth_rule_defined"]
    not azure_issue["event_hub_instance_has_auth_rule_defined"]
}

event_hub_instance_has_auth_rule_defined = false {
    lower(input.resources[_].type) == "azurerm_eventhub"
    azure_attribute_absence["event_hub_instance_has_auth_rule_defined"]
}

event_hub_instance_has_auth_rule_defined = false {
    lower(input.resources[_].type) == "azurerm_eventhub"
    azure_issue["event_hub_instance_has_auth_rule_defined"]
}

event_hub_instance_has_auth_rule_defined_err = "azurerm_eventhub_authorization_rule resoruce or relation between azurerm_eventhub is missing" {
    lower(input.resources[_].type) == "azurerm_eventhub"
    azure_attribute_absence["event_hub_instance_has_auth_rule_defined"]
} else = "Authorization rules on the Event Hub instance is not defined" {
    lower(input.resources[_].type) == "azurerm_eventhub"
    azure_issue["event_hub_instance_has_auth_rule_defined"]
}

event_hub_instance_has_auth_rule_defined_metadata := {
    "Policy Code": "PR-AZR-TRF-EHB-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Authorization rules on the Event Hub instance should be defined",
    "Policy Description": "Audit existence of authorization rules on Event Hub entities to grant least-privileged access",
    "Resource Type": "azurerm_eventhub",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/eventhub"
}