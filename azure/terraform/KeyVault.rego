package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault
# It's possible to define Key Vault Access Policies both within the azurerm_key_vault resource via the access_policy block and by using the azurerm_key_vault_access_policy resource. 
# However it's not possible to use both methods to manage Access Policies within a KeyVault, since there'll be conflicts.

# PR-AZR-TRF-KV-001

default KeyVault = null

azure_attribute_absence["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    access_policy := resource.properties.access_policy[_]
    not access_policy.key_permissions
    not access_policy.secret_permissions
    not access_policy.certificate_permissions
    not access_policy.storage_permissions
}

azure_issue["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    access_policy := resource.properties.access_policy[_]
    count(access_policy.key_permissions) == 0
    count(access_policy.secret_permissions) == 0
    count(access_policy.certificate_permissions) == 0
    count(access_policy.storage_permissions) == 0
}

KeyVault = false {
    azure_attribute_absence["KeyVault"]
}

KeyVault {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["KeyVault"]
    not azure_issue["KeyVault"]
}

KeyVault = false {
    azure_issue["KeyVault"]
}

KeyVault_err = "access_policy block property 'key_permissions' or 'secret_permissions' or 'certificate_permissions' or 'storage_permissions' is missing from the azurerm_key_vault resource." {
    azure_attribute_absence["KeyVault"]
} else = "Currently no principal has access to Keyvault" {
    azure_issue["KeyVault"]
}

KeyVault_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure at least one principal has access to Keyvault",
    "Policy Description": "Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.",
    "Resource Type": "azurerm_key_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
}



# PR-AZR-TRF-KV-002
# As of 2020-12-15 Azure now requires that Soft Delete is enabled on Key Vaults and this can no longer be disabled. 
# Version v2.42 of the Azure Provider and later ignore the value of the soft_delete_enabled field and force this value to be true - 
# as such this field can be safely removed from your Terraform Configuration. This field will be removed in version 3.0 of the Azure Provider.
default enableSoftDelete = null
azure_attribute_absence ["enableSoftDelete"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    not resource.properties.soft_delete_enabled
}

azure_issue ["enableSoftDelete"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    resource.properties.soft_delete_enabled != true
}

enableSoftDelete {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["enableSoftDelete"]
    not azure_issue["enableSoftDelete"]
}

enableSoftDelete = false {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_attribute_absence["enableSoftDelete"]
    not azure_issue["enableSoftDelete"]
}

enableSoftDelete_err = "'Soft Delete' setting is currently not enabled for Key Vault" {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.",
    "Resource Type": "azurerm_key_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
}


# PR-AZR-TRF-KV-003

default enablePurgeProtection = null

azure_attribute_absence ["enablePurgeProtection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    not resource.properties.purge_protection_enabled
}

azure_issue ["enablePurgeProtection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    resource.properties.purge_protection_enabled != true
}

enablePurgeProtection {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["enablePurgeProtection"]
    not azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_attribute_absence["enablePurgeProtection"]
}

enablePurgeProtection_err = "azurerm_key_vault property 'purge_protection_enabled' is missing from the resource." {
    azure_attribute_absence["enableSoftDelete"]
} else = "Purge protection is currently not enabled on Key vault" {
    azure_issue["enableSoftDelete"]
}

enablePurgeProtection_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Key vault should have purge protection enabled",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation",
    "Resource Type": "azurerm_key_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key
#
# PR-AZR-TRF-KV-004
#

default kv_keys_expire = null

azure_attribute_absence["kv_keys_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_key"
    not resource.properties.expiration_date
}

azure_issue["kv_keys_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_key"
    not regex.match("^[2-9]\\d{3}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]).*",
        resource.properties.expiration_date)
}

kv_keys_expire {
    lower(input.resources[_].type) == "azurerm_key_vault_key"
    not azure_attribute_absence["kv_keys_expire"]
    not azure_issue["kv_keys_expire"]
}

kv_keys_expire = false {
    azure_attribute_absence["kv_keys_expire"]
}

kv_keys_expire = false {
    azure_issue["kv_keys_expire"]
}

kv_keys_expire_err = "azurerm_key_vault_key property 'expiration_date' need to be exist. Its missing from the resource." {
    azure_attribute_absence["kv_keys_expire"]
} else = "Azure Key Vault key does not have any expiration date" {
    azure_issue["kv_keys_expire"]
}

kv_keys_expire_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault keys should have an expiration date",
    "Policy Description": "This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each key.",
    "Resource Type": "azurerm_key_vault_key",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key"
}

# https://docs.microsoft.com/en-us/azure/templates/azurerm_key_vault_secret
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret
#
# PR-AZR-TRF-KV-005
#

default kv_expire = null

azure_attribute_absence["kv_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_secret"
    not resource.properties.expiration_date
}

azure_issue["kv_expire"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault_secret"
    not regex.match("^[2-9]\\d{3}-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01]).*",
        resource.properties.expiration_date)
}

kv_expire {
    lower(input.resources[_].type) == "azurerm_key_vault_secret"
    not azure_attribute_absence["kv_expire"]
    not azure_issue["kv_expire"]
}

kv_expire = false {
    azure_attribute_absence["kv_expire"]
}

kv_expire = false {
    azure_issue["kv_expire"]
}

kv_expire_err = "azurerm_key_vault_secret property 'expiration_date' need to be exist. Its missing from the resource." {
    azure_attribute_absence["kv_expire"]
} else = "Azure Key Vault secrets does not have any expiration date" {
    azure_issue["kv_expire"]
}

kv_expire_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault secrets should have an expiration date",
    "Policy Description": "This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.",
    "Resource Type": "azurerm_key_vault_secret",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret"
}

# PR-AZR-TRF-KV-006

default kv_public_network_access_disabled = null

azure_attribute_absence ["kv_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    not resource.properties.network_acls
}

azure_attribute_absence ["kv_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    network_acls := resource.properties.network_acls[_]
    not network_acls.default_action
}

azure_issue ["kv_public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    network_acls := resource.properties.network_acls[_]
    lower(network_acls.default_action) != "deny"
}

kv_public_network_access_disabled {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["kv_public_network_access_disabled"]
    not azure_issue["kv_public_network_access_disabled"]
}

kv_public_network_access_disabled = false {
    azure_issue["kv_public_network_access_disabled"]
}

kv_public_network_access_disabled = false {
    azure_attribute_absence["kv_public_network_access_disabled"]
}

kv_public_network_access_disabled_err = "azurerm_key_vault property 'default_action' under 'network_acls' block is missing from the resource." {
    azure_attribute_absence["kv_public_network_access_disabled"]
} else = "Public network access is currently not disabled in Key vault" {
    azure_issue["kv_public_network_access_disabled"]
}

kv_public_network_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault should disable public network access",
    "Policy Description": "Disable public network access for your key vault so that it's not accessible over the public internet. This can reduce data leakage risks.",
    "Resource Type": "azurerm_key_vault",
    "Policy Help URL": "https://github.com/Azure/azure-policy/blob/master/built-in-policies/policyDefinitions/Key%20Vault/AzureKeyVaultFirewallEnabled_Audit.json",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
}

# PR-AZR-TRF-KV-007

default kv_allow_bypass_for_azure_services = null

azure_attribute_absence ["kv_allow_bypass_for_azure_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    not resource.properties.network_acls
}

azure_attribute_absence ["kv_allow_bypass_for_azure_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    network_acls := resource.properties.network_acls[_]
    not network_acls.bypass
}

azure_issue ["kv_allow_bypass_for_azure_services"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    network_acls := resource.properties.network_acls[_]
    lower(network_acls.bypass) != "azureservices"
}

kv_allow_bypass_for_azure_services {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["kv_allow_bypass_for_azure_services"]
    not azure_issue["kv_allow_bypass_for_azure_services"]
}

kv_allow_bypass_for_azure_services = false {
    azure_issue["kv_allow_bypass_for_azure_services"]
}

kv_allow_bypass_for_azure_services = false {
    azure_attribute_absence["kv_allow_bypass_for_azure_services"]
}

kv_allow_bypass_for_azure_services_err = "azurerm_key_vault property 'bypass' under 'network_acls' block is missing from the resource." {
    azure_attribute_absence["kv_allow_bypass_for_azure_services"]
} else = "Traffic from Trusted AzureServices are not currently allowing to bypass in Key vault network rules" {
    azure_issue["kv_allow_bypass_for_azure_services"]
}

kv_allow_bypass_for_azure_services_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Key Vault Trusted Microsoft Services access should be enabled",
    "Policy Description": "When you enable the Key Vault Firewall, you will be given an option to 'Allow Trusted Microsoft Services to bypass this firewall'. The trusted services list encompasses services where Microsoft controls all of the code that runs on the service.",
    "Resource Type": "azurerm_key_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
}

# PR-AZR-TRF-KV-008

default kv_service_endpoint_enabled = null

azure_attribute_absence ["kv_service_endpoint_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    not resource.properties.network_acls
}

azure_attribute_absence ["kv_service_endpoint_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    network_acls := resource.properties.network_acls[_]
    not network_acls.virtual_network_subnet_ids
}

azure_issue ["kv_service_endpoint_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    network_acls := resource.properties.network_acls[_]
    count(network_acls.virtual_network_subnet_ids) == 0
}

kv_service_endpoint_enabled {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["kv_service_endpoint_enabled"]
    not azure_issue["kv_service_endpoint_enabled"]
}

kv_service_endpoint_enabled = false {
    azure_issue["kv_service_endpoint_enabled"]
}

kv_service_endpoint_enabled = false {
    azure_attribute_absence["kv_service_endpoint_enabled"]
}

kv_service_endpoint_enabled_err = "azurerm_key_vault array property 'virtual_network_subnet_ids' under 'network_acls' block is missing from the resource." {
    azure_attribute_absence["kv_service_endpoint_enabled"]
} else = "Azure KeyVault currently not allowing access from virtual network service endpoint" {
    azure_issue["kv_service_endpoint_enabled"]
}

kv_service_endpoint_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure KeyVault should allow access from virtual network service endpoint",
    "Policy Description": "This policy will identify if One or more Subnet ID's have access to this Key Vault. Will warn if not found.",
    "Resource Type": "azurerm_key_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
}

# PR-AZR-TRF-KV-009

default kv_usage_private_enpoint = null

azure_attribute_absence ["kv_usage_private_enpoint"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

azure_issue ["kv_usage_private_enpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
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

kv_usage_private_enpoint = false {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_attribute_absence["kv_usage_private_enpoint"]
}

kv_usage_private_enpoint {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_attribute_absence["kv_usage_private_enpoint"]
    not azure_issue["kv_usage_private_enpoint"]
}

kv_usage_private_enpoint = false {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_issue["kv_usage_private_enpoint"]
}

kv_usage_private_enpoint_err = "azurerm_key_vault should have link with azurerm_private_endpoint and azurerm_private_endpoint's private_service_connection either need to have 'private_connection_resource_id' or 'private_connection_resource_alias' property. Seems there is no link established or mentioed properties are missing." {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_attribute_absence["kv_usage_private_enpoint"]
} else = "Azure KeyVault currently not using private link" {
    lower(input.resources[_].type) == "azurerm_key_vault"
    azure_issue["kv_usage_private_enpoint"]
}

kv_usage_private_enpoint_metadata := {
    "Policy Code": "PR-AZR-TRF-KV-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure KeyVault should use private link",
    "Policy Description": "Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure KeyVault, data leakage risks are reduced.",
    "Resource Type": "azurerm_key_vault",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault"
}