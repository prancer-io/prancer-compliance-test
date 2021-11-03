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


# PR-AZR-TRF-KV-003

default enablePurgeProtection = null

azure_issue ["enablePurgeProtection"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_key_vault"
    not resource.properties.purge_protection_enabled
}

enablePurgeProtection {
    lower(input.resources[_].type) == "azurerm_key_vault"
    not azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_issue["enablePurgeProtection"]
}

enablePurgeProtection_err = "Purge protection is currently not enabled on Key vault" {
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