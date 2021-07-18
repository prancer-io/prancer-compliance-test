package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults

# PR-AZR-0107-ARM

default KeyVault = null

azure_attribute_absence["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.accessPolicies[_].permissions.keys
    not resource.properties.accessPolicies[_].permissions.secrets
    not resource.properties.accessPolicies[_].permissions.certificates
}


azure_issue["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    count(resource.properties.accessPolicies[_].permissions.keys) == 0
    count(resource.properties.accessPolicies[_].permissions.secrets) == 0
    count(resource.properties.accessPolicies[_].permissions.certificates) == 0
}

KeyVault {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_issue["KeyVault"]
    not azure_attribute_absence["KeyVault"]
}

KeyVault = false {
    azure_issue["KeyVault"]
}

KeyVault = false {
    azure_attribute_absence["KeyVault"]
}

KeyVault_err = "Ensure at least one principal has access to Keyvault" {
    azure_issue["KeyVault"]
}


KeyVault_miss_err = "Ensure at least one principal has access to Keyvault" {
    azure_attribute_absence["KeyVault"]
}

KeyVault_metadata := {
    "Policy Code": "PR-AZR-0107-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure at least one principal has access to Keyvault",
    "Policy Description": "Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}



# PR-AZR-0108-ARM

default enableSoftDelete = null
azure_attribute_absence ["enableSoftDelete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.enableSoftDelete
}

azure_issue ["enableSoftDelete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    resource.properties.enableSoftDelete != true
}

enableSoftDelete {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_issue["enableSoftDelete"]
    not azure_attribute_absence["enableSoftDelete"]
}

enableSoftDelete = false {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete = false {
    azure_attribute_absence["enableSoftDelete"]
}


enableSoftDelete_err = "Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault" {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete_miss_err = "Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault" {
    azure_attribute_absence["enableSoftDelete"]
}


enableSoftDelete_metadata := {
    "Policy Code": "PR-AZR-0108-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}




# PR-AZR-0109-ARM

default enablePurgeProtection = null

azure_attribute_absence ["enablePurgeProtection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    not resource.properties.enablePurgeProtection
}


azure_issue ["enablePurgeProtection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    resource.properties.enablePurgeProtection != true
}


enablePurgeProtection {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_issue["enablePurgeProtection"]
    not azure_attribute_absence["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_attribute_absence["enablePurgeProtection"]
}


enablePurgeProtection_err = "Key vault should have purge protection enabled" {
    azure_issue["enableSoftDelete"]
}

enablePurgeProtection_miss_err = "Key vault should have purge protection enabled" {
    azure_attribute_absence["enableSoftDelete"]
}


enablePurgeProtection_metadata := {
    "Policy Code": "PR-AZR-0109-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Key vault should have purge protection enabled",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}