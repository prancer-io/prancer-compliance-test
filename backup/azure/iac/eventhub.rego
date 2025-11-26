package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }


#
# PR-AZR-ARM-EHB-001
#

default event_hub_namespace_has_local_auth_disabled = null
# Default value is false
azure_attribute_absence["event_hub_namespace_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    not resource.properties.disableLocalAuth
}

azure_issue["event_hub_namespace_has_local_auth_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    resource.properties.disableLocalAuth != true
}

event_hub_namespace_has_local_auth_disabled {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    not azure_attribute_absence["event_hub_namespace_has_local_auth_disabled"]
    not azure_issue["event_hub_namespace_has_local_auth_disabled"]
}

event_hub_namespace_has_local_auth_disabled = false {
    azure_attribute_absence["event_hub_namespace_has_local_auth_disabled"]
}

event_hub_namespace_has_local_auth_disabled = false {
    azure_issue["event_hub_namespace_has_local_auth_disabled"]
}

event_hub_namespace_has_local_auth_disabled_err = "microsoft.eventhub/namespaces resoruce property disableLocalAuth is missing" {
    azure_attribute_absence["event_hub_namespace_has_local_auth_disabled"]
} else = "Azure Event Hub namespaces local authentication is currently not disabled" {
    azure_issue["event_hub_namespace_has_local_auth_disabled"]
}

event_hub_namespace_has_local_auth_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-EHB-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Hub namespaces should have local authentication methods disabled",
    "Policy Description": "Disabling local authentication methods improves security by ensuring that Azure Event Hub namespaces exclusively require Azure Active Directory identities for authentication. Learn more at: https://aka.ms/disablelocalauth-eh.",
    "Resource Type": "Microsoft.EventHub/namespaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventhub/namespaces?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-EHB-002
#

default event_hub_namespace_has_double_encryption_enabled = null

azure_attribute_absence["event_hub_namespace_has_double_encryption_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    not resource.properties.encryption
}

azure_attribute_absence["event_hub_namespace_has_double_encryption_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    not resource.properties.encryption.requireInfrastructureEncryption
}

azure_issue["event_hub_namespace_has_double_encryption_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    resource.properties.encryption.requireInfrastructureEncryption != true
}

event_hub_namespace_has_double_encryption_enabled {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    not azure_attribute_absence["event_hub_namespace_has_double_encryption_enabled"]
    not azure_issue["event_hub_namespace_has_double_encryption_enabled"]
}

event_hub_namespace_has_double_encryption_enabled = false {
    azure_attribute_absence["event_hub_namespace_has_double_encryption_enabled"]
}

event_hub_namespace_has_double_encryption_enabled = false {
    azure_issue["event_hub_namespace_has_double_encryption_enabled"]
}

event_hub_namespace_has_double_encryption_enabled_err = "microsoft.eventhub/namespaces resoruce property encryption.requireInfrastructureEncryption is missing" {
    azure_attribute_absence["event_hub_namespace_has_double_encryption_enabled"]
} else = "Azure Event Hub namespaces double encryption is currently not disabled" {
    azure_issue["event_hub_namespace_has_double_encryption_enabled"]
}

event_hub_namespace_has_double_encryption_enabled_metadata := {
    "Policy Code": "PR-AZR-ARM-EHB-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Event Hub namespaces should have double encryption enabled",
    "Policy Description": "Enabling double encryption helps protect and safeguard your data to meet your organizational security and compliance commitments. When double encryption has been enabled, data in the storage account is encrypted twice, once at the service level and once at the infrastructure level, using two different encryption algorithms and two different keys.",
    "Resource Type": "Microsoft.EventHub/namespaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventhub/namespaces?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.eventhub/namespaces/privateendpointconnections?pivots=deployment-language-arm-template
# PR-AZR-ARM-EHB-004

default event_hub_namespace_configured_with_private_endpoint = null

azure_attribute_absence["event_hub_namespace_configured_with_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.eventhub/namespaces/privateendpointconnections"; c := 1]) == 0
}

azure_attribute_absence["event_hub_namespace_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces/privateendpointconnections"
    not resource.dependsOn
}

azure_attribute_absence["event_hub_namespace_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState
}

azure_attribute_absence["event_hub_namespace_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState.status
}

azure_issue["event_hub_namespace_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.eventhub/namespaces/privateendpointconnections";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.privateLinkServiceConnectionState.status) == "approved";
              c := 1]) == 0
}

event_hub_namespace_configured_with_private_endpoint {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    not azure_attribute_absence["event_hub_namespace_configured_with_private_endpoint"]
    not azure_issue["event_hub_namespace_configured_with_private_endpoint"]
}

event_hub_namespace_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    azure_attribute_absence["event_hub_namespace_configured_with_private_endpoint"]
}

event_hub_namespace_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    azure_issue["event_hub_namespace_configured_with_private_endpoint"]
}

event_hub_namespace_configured_with_private_endpoint_err = "Azure Event Hub namespaces currently dont have private endpoints configured" {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    azure_issue["event_hub_namespace_configured_with_private_endpoint"]
} else = "Microsoft.EventHub/namespaces/privateEndpointConnections resoruce property 'privateLinkServiceConnectionState.status' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    azure_attribute_absence["event_hub_namespace_configured_with_private_endpoint"]
}

event_hub_namespace_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-ARM-EHB-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Event Hub namespaces should have private endpoints configured",
    "Policy Description": "Private endpoints connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to Event Hub namespaces, you can reduce data leakage risks. Learn more at: https://docs.microsoft.com/azure/event-hubs/private-link-service.",
    "Resource Type": "Microsoft.EventHub/namespaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventhub/namespaces?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-EHB-005
#

default event_hub_namespace_usage_custom_managed_key_for_encryption = null

azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    not resource.properties.encryption
}

azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    not resource.properties.encryption.keySource
}

azure_issue["event_hub_namespace_usage_custom_managed_key_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces"
    lower(resource.properties.encryption.keySource) != "microsoft.keyvault"
}

event_hub_namespace_usage_custom_managed_key_for_encryption {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces"
    not azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"]
    not azure_issue["event_hub_namespace_usage_custom_managed_key_for_encryption"]
}

event_hub_namespace_usage_custom_managed_key_for_encryption = false {
    azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"]
}

event_hub_namespace_usage_custom_managed_key_for_encryption = false {
    azure_issue["event_hub_namespace_usage_custom_managed_key_for_encryption"]
}

event_hub_namespace_usage_custom_managed_key_for_encryption_err = "microsoft.eventhub/namespaces resoruce property encryption.keySource is missing" {
    azure_attribute_absence["event_hub_namespace_usage_custom_managed_key_for_encryption"]
} else = "Azure Event Hub namespaces currently not using customer-managed key for encryption" {
    azure_issue["event_hub_namespace_usage_custom_managed_key_for_encryption"]
}

event_hub_namespace_usage_custom_managed_key_for_encryption_metadata := {
    "Policy Code": "PR-AZR-ARM-EHB-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Event Hub namespaces should use customer-managed key for encryption",
    "Policy Description": "Azure Event Hubs supports the option of encrypting data at rest with either Microsoft-managed keys (default) or customer-managed keys. Choosing to encrypt data using customer-managed keys enables you to assign, rotate, disable, and revoke access to the keys that Event Hub will use to encrypt data in your namespace. Note that Event Hub only supports encryption with customer-managed keys for namespaces in dedicated clusters.",
    "Resource Type": "Microsoft.EventHub/namespaces",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventhub/namespaces?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-EHB-006
#

default event_hub_namespace_only_has_rootmanage_sharedaccesskey = null

azure_attribute_absence["event_hub_namespace_only_has_rootmanage_sharedaccesskey"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces/authorizationrules"
    not resource.name
}

azure_issue["event_hub_namespace_only_has_rootmanage_sharedaccesskey"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.eventhub/namespaces/authorizationrules"
    lower(resource.name) != "rootmanagesharedaccesskey"
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey {
    lower(input.resources[_].type) == "microsoft.eventhub/namespaces/authorizationrules"
    not azure_attribute_absence["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
    not azure_issue["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey = false {
    azure_attribute_absence["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey = false {
    azure_issue["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey_err = "Microsoft.EventHub/namespaces/authorizationRules resoruce name is missing" {
    azure_attribute_absence["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
} else = "Azure Event Hub namespaces currently dont have RootManageSharedAccessKey as only authorization rules" {
    azure_issue["event_hub_namespace_only_has_rootmanage_sharedaccesskey"]
}

event_hub_namespace_only_has_rootmanage_sharedaccesskey_metadata := {
    "Policy Code": "PR-AZR-ARM-EHB-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "All authorization rules except RootManageSharedAccessKey should be removed from Event Hub namespace",
    "Policy Description": "Event Hub clients should not use a namespace level access policy that provides access to all queues and topics in a namespace. To align with the least privilege security model, you should create access policies at the entity level for queues and topics to provide access to only the specific entity",
    "Resource Type": "Microsoft.EventHub/namespaces/authorizationRules",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventhub/2017-04-01/namespaces/authorizationrules?pivots=deployment-language-arm-template"
}


#
# PR-AZR-ARM-EHB-007
#

default event_hub_instance_has_auth_rule_defined = null

azure_attribute_absence["event_hub_instance_has_auth_rule_defined"] {
    count([c | lower(input.resources[_].type) == "microsoft.eventhub/namespaces/eventhubs/authorizationrules"; c := 1]) == 0
}

event_hub_instance_has_auth_rule_defined {
    lower(input.resources[_].type) == "Microsoft.EventHub/namespaces/eventhubs"
    not azure_attribute_absence["event_hub_instance_has_auth_rule_defined"]
}

event_hub_instance_has_auth_rule_defined = false {
    lower(input.resources[_].type) == "Microsoft.EventHub/namespaces/eventhubs"
    azure_attribute_absence["event_hub_instance_has_auth_rule_defined"]
}

event_hub_instance_has_auth_rule_defined_err = "Microsoft.EventHub/namespaces/eventhubs/authorizationRules resoruce is missing" {
    lower(input.resources[_].type) == "Microsoft.EventHub/namespaces/eventhubs"
    azure_attribute_absence["event_hub_instance_has_auth_rule_defined"]
} 

event_hub_instance_has_auth_rule_defined_metadata := {
    "Policy Code": "PR-AZR-ARM-EHB-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Authorization rules on the Event Hub instance should be defined",
    "Policy Description": "Audit existence of authorization rules on Event Hub entities to grant least-privileged access",
    "Resource Type": "Microsoft.EventHub/namespaces/eventhubs",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.eventhub/namespaces/eventhubs?pivots=deployment-language-arm-template"
}