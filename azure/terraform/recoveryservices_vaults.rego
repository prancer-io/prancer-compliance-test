package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/recovery_services_vault
#
# PR-AZR-TRF-RSV-001
#

default recoveryservices_vaults_usage_custom_managed_keys_for_encryption = null

azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_recovery_services_vault"
    not resource.properties.encryption
}

azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_recovery_services_vault"
    encryption := resource.properties.encryption[_]
    not encryption.key_id
}

azure_issue["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_recovery_services_vault"
    encryption := resource.properties.encryption[_]
    trim(encryption.key_id, " ") == ""
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption {
    lower(input.resources[_].type) == "azurerm_recovery_services_vault"
    not azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
    not azure_issue["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption = false {
    azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption = false {
    azure_issue["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption_err = "azurerm_recovery_services_vault property 'encryption.key_id' need to be exist. Currently its missing from the resource." {
    azure_attribute_absence["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
} else = "Azure Recovery Services vaults is currently not using customer-managed keys for encryption" {
    azure_issue["recoveryservices_vaults_usage_custom_managed_keys_for_encryption"]
}

recoveryservices_vaults_usage_custom_managed_keys_for_encryption_metadata := {
    "Policy Code": "PR-AZR-TRF-RSV-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Recovery Services vaults should use customer-managed keys for encryption",
    "Policy Description": "Use customer-managed keys to manage the encryption at rest of your backup data. By default, customer data is encrypted with service-managed keys, but customer-managed keys are commonly required to meet regulatory compliance standards. Customer-managed keys enable the data to be encrypted with an Azure Key Vault key created and owned by you. You have full control and responsibility for the key lifecycle, including rotation and management. Learn more at https://aka.ms/AB-CmkEncryption.",
    "Resource Type": "azurerm_recovery_services_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/recovery_services_vault"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/recovery_services_vault
#
# PR-AZR-TRF-RSV-002
#

default recoveryservices_vaults_configured_with_private_endpoint = null

azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

azure_issue["recoveryservices_vaults_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_recovery_services_vault"
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_id, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_id, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_alias, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_alias, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
}

recoveryservices_vaults_configured_with_private_endpoint {
    lower(input.resources[_].type) == "azurerm_recovery_services_vault"
    not azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"]
    not azure_issue["recoveryservices_vaults_configured_with_private_endpoint"]
}

recoveryservices_vaults_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "azurerm_recovery_services_vault"
    azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"]
}

recoveryservices_vaults_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "azurerm_recovery_services_vault"
    azure_issue["recoveryservices_vaults_configured_with_private_endpoint"]
}

recoveryservices_vaults_configured_with_private_endpoint_err = "Resource azurerm_recovery_services_vault and azurerm_private_endpoint need to be exist and id of azurerm_recovery_services_vault need to be set on private_service_connection[_].private_connection_resource_id property of azurerm_private_endpoint." {
    lower(input.resources[_].type) == "azurerm_recovery_services_vault"
    azure_attribute_absence["recoveryservices_vaults_configured_with_private_endpoint"]
} else = "Azure Recovery Services vaults currently dont have private link configured" {
    lower(input.resources[_].type) == "azurerm_recovery_services_vault"
    azure_issue["recoveryservices_vaults_configured_with_private_endpoint"]
}

recoveryservices_vaults_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-TRF-RSV-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Recovery Services vaults should use private link",
    "Policy Description": "Azure Private Link lets you connect your virtual network to Azure services without a public IP address at the source or destination. The Private Link platform handles the connectivity between the consumer and services over the Azure backbone network. By mapping private endpoints to Azure Recovery Services vaults, data leakage risks are reduced. Learn more about private links at: https://aka.ms/AB-PrivateEndpoints.",
    "Resource Type": "azurerm_recovery_services_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/recovery_services_vault"
}