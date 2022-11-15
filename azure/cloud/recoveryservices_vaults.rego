package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://learn.microsoft.com/en-us/azure/templates/microsoft.recoveryservices/vaults?pivots=deployment-language-arm-template

#
# PR-AZR-CLD-RSV-001
#

default recoveryservices_vaults_usage_custom_managed_keys_for_encryption = null

azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.recoveryservices/vaults"
    not resource.properties.encryption.keyVaultProperties.keyUri
}

azure_issue["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.recoveryservices/vaults"
    trim(resource.properties.encryption.keyVaultProperties.keyUri, " ") == ""
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption {
    lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    not azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
    not azure_issue["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption = false {
    azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption = false {
    azure_issue["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption_err = "microsoft.recoveryservices/vaults resoruce property encryption.keyVaultProperties.keyUri is missing" {
    azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
} else = "Azure Recovery Services vaults is currently not using customer-managed keys for encryption" {
    azure_issue["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption_metadata := {
    "Policy Code": "PR-AZR-CLD-RSV-001",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Recovery Services vaults should use customer-managed keys for encryption",
    "Policy Description": "Use customer-managed keys to manage the encryption at rest of your backup data. By default, customer data is encrypted with service-managed keys, but customer-managed keys are commonly required to meet regulatory compliance standards. Customer-managed keys enable the data to be encrypted with an Azure Key Vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more at https://aka.ms/AB-CmkEncryption.",
    "Resource Type": "Microsoft.RecoveryServices/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.recoveryservices/vaults?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.recoveryservices/vaults?pivots=deployment-language-arm-template

#
# PR-AZR-CLD-RSV-002
#

default recoveryservices_vaults_configured_with_private_endpoint = null

azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.recoveryservices/vaults/privateendpointconnections"; c := 1]) == 0
}

azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.recoveryservices/vaults/privateendpointconnections"
    not resource.dependsOn
}

azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.recoveryservices/vaults/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState
}

azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.recoveryservices/vaults/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState.status
}

azure_issue["recoveryservices_vaults_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.recoveryservices/vaults"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.recoveryservices/vaults/privateendpointconnections";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.privateLinkServiceConnectionState.status) == "approved";
              c := 1]) == 0
}

recoveryservices_vaults_configured_with_private_endpoint {
    lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    not azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"]
    not azure_issue["recoveryservices_vaults_configured_with_private_endpoint"]
}

recoveryservices_vaults_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"]
}

recoveryservices_vaults_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    azure_issue["recoveryservices_vaults_configured_with_private_endpoint"]
}

recoveryservices_vaults_configured_with_private_endpoint_err = "Azure Recovery Services vaults currently dont have private link configured" {
    lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    azure_issue["recoveryservices_vaults_configured_with_private_endpoint"]
} else = "Microsoft.RecoveryServices/vaults/privateEndpointConnections resoruce property 'privateLinkServiceConnectionState.status' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.recoveryservices/vaults"
    azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"]
}

recoveryservices_vaults_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-CLD-RSV-002",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure Recovery Services vaults should use private link",
    "Policy Description": "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to Azure Recovery Services vaults, data leakage risks are reduced. Learn more about private links at: https://aka.ms/AB-PrivateEndpoints.",
    "Resource Type": "Microsoft.RecoveryServices/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.recoveryservices/vaults?pivots=deployment-language-arm-template"
}