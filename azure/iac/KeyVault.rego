package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults

# PR-AZR-0107-ARM

default KeyVault = null
azure_issue ["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    count(resource.properties.accessPolicies.permissions.keys) == 0
    count(resource.properties.accessPolicies.permissions.secrets) == 0
    count(resource.properties.accessPolicies.permissions.certificates) == 0
}

KeyVault {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_issue["KeyVault"]
}

KeyVault = false {
    azure_issue["KeyVault"]
}


KeyVault_err = "ENSURE THAT KEYVAULT IS IN USE" {
    azure_issue["KeyVault"]
}


KeyVault_metadata := {
    "Policy Code": "PR-AZR-0107-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "ENSURE THAT KEYVAULT IS IN USE",
    "Policy Description": "Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}



# PR-AZR-0108-ARM

default enableSoftDelete = null
azure_issue ["enableSoftDelete"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    resource.properties.enableSoftDelete != true
}

enableSoftDelete {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_issue["enableSoftDelete"]
}

enableSoftDelete = false {
    azure_issue["enableSoftDelete"]
}


enableSoftDelete_err = "ENSURE THE KEY VAULT IS RECOVERABLE - ENABLE 'SOFT DELETE' SETTING FOR A KEY VAULT" {
    azure_issue["enableSoftDelete"]
}


enableSoftDelete_metadata := {
    "Policy Code": "PR-AZR-0108-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "ENSURE THE KEY VAULT IS RECOVERABLE - ENABLE 'SOFT DELETE' SETTING FOR A KEY VAULT",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}




# PR-AZR-0109-ARM

default enablePurgeProtection = null
azure_issue ["enablePurgeProtection"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    resource.properties.enablePurgeProtection != true
}

enablePurgeProtection {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_issue["enablePurgeProtection"]
}


enablePurgeProtection_err = "KEY VAULT SHOULD HAVE PURGE PROTECTION ENABLED" {
    azure_issue["enableSoftDelete"]
}


enablePurgeProtection_metadata := {
    "Policy Code": "PR-AZR-0109-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "KEY VAULT SHOULD HAVE PURGE PROTECTION ENABLED",
    "Policy Description": "The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation",
    "Resource Type": "microsoft.keyvault/vaults",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults"
}