package rule

# https://docs.microsoft.com/en-us/rest/api/keyvault/vaults/get

# PR-AZR-KV-001

default KeyVault = null

azure_attribute_absence["KeyVault"] {
    lower(input.type) == "microsoft.keyvault/vaults"
    accessPolicy := input.resource.properties.accessPolicies[_]
    not accessPolicy.permissions.keys
    not accessPolicy.permissions.secrets
    not accessPolicy.permissions.certificates
    not accessPolicy.permissions.storage
}

azure_issue["KeyVault"] {
    lower(input.type) == "microsoft.keyvault/vaults"
    accessPolicy := input.resource.properties.accessPolicies[_]
    count(accessPolicy.permissions.keys) == 0
    count(accessPolicy.permissions.secrets) == 0
    count(accessPolicy.permissions.certificates) == 0
    count(accessPolicy.permissions.storage) == 0
}


KeyVault {
    lower(input.type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["KeyVault"]
    not azure_issue["KeyVault"]
}

KeyVault = false {
    azure_issue["KeyVault"]
}

KeyVault = false {
    azure_attribute_absence["KeyVault"]
}

KeyVault_err = "accessPolicy property 'permissions.keys' or 'permissions.secrets' or 'permissions.certificates' or 'permissions.storage' is missing from the microsoft.keyvault/vaults resource." {
    azure_attribute_absence["KeyVault"]
} else = "Currently no principal has access to Keyvault" {
    azure_issue["KeyVault"]
}

KeyVault_metadata := {
    "Policy Code": "PR-AZR-KV-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language":  "template",
    "Policy Title": "Ensure that keyvault is in use",
    "Policy Description": "Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/keyvault/vaults/get"
}


# PR-AZR-KV-002

default enableSoftDelete = null
azure_attribute_absence ["enableSoftDelete"] {
    lower(input.type) == "microsoft.keyvault/vaults"
    not input.properties.enableSoftDelete
}

azure_issue ["enableSoftDelete"] {
    lower(input.type) == "microsoft.keyvault/vaults"
    input.properties.enableSoftDelete != true
}


enableSoftDelete {
    lower(input.type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["enableSoftDelete"]
    not azure_issue["enableSoftDelete"]
}

enableSoftDelete = false {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete {
    azure_attribute_absence["enableSoftDelete"]
    not azure_issue["enableSoftDelete"]
}

enableSoftDelete_err = "'Soft Delete' setting is currently not enabled for Key Vault" {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete_metadata := {
    "Policy Code": "PR-AZR-KV-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/keyvault/vaults/get"
}



# PR-AZR-KV-003

default enablePurgeProtection = null

azure_attribute_absence ["enablePurgeProtection"] {
    lower(input.type) == "microsoft.keyvault/vaults"
    not input.properties.enablePurgeProtection
}

azure_issue ["enablePurgeProtection"] {
    lower(input.type) == "microsoft.keyvault/vaults"
    input.properties.enablePurgeProtection != true
}

enablePurgeProtection {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["enablePurgeProtection"]
    not azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_attribute_absence["enablePurgeProtection"]
}

enablePurgeProtection_err = "microsoft.keyvault/vaults resoruce property enablePurgeProtection is missing" {
    azure_attribute_absence["enableSoftDelete"]
} else = "Purge protection is currently not enabled on Key vault" {
    azure_issue["enableSoftDelete"]
}

enablePurgeProtection_metadata := {
    "Policy Code": "PR-AZR-KV-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Key vault should have purge protection enabled",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/keyvault/vaults/get"
}