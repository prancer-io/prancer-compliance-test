package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults

# PR-AZR-0107-ARM

default KeyVault = null

azure_attribute_absence["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    accessPolicy := resource.properties.accessPolicies[_]
    not accessPolicy.permissions.keys
    not accessPolicy.permissions.secrets
    not accessPolicy.permissions.certificates
}


azure_issue["KeyVault"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.keyvault/vaults"
    accessPolicy := resource.properties.accessPolicies[_]
    count(accessPolicy.permissions.keys) == 0
    count(accessPolicy.permissions.secrets) == 0
    count(accessPolicy.permissions.certificates) == 0
}

KeyVault {
    lower(input.resources[_].type) == "microsoft.keyvault/vaults"
    not azure_attribute_absence["KeyVault"]
    not azure_issue["KeyVault"]
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

# Rezoan: This rule is not being used. We should merge this rule with KeyVault_err in a OR logic. Farshid to confirm. 
# Consider this comment for each every rule that is similar to this one.
# if we merge, the message should be same for both. Otherwise message should be different based on purpose.
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
    not azure_attribute_absence["enableSoftDelete"]
    not azure_issue["enableSoftDelete"]
}

enableSoftDelete = false {
    azure_issue["enableSoftDelete"]
}

enableSoftDelete = false {
    azure_attribute_absence["enableSoftDelete"]
}


enableSoftDelete_err = "'Soft Delete' setting is currently not enabled for Key Vault" {
    azure_issue["enableSoftDelete"]
}

# Rezoan: This rule is not being used. We should merge this rule with enableSoftDelete_err in a OR logic. Farshid to confirm. 
# Consider this comment for each every rule that is similar to this one.
# if we merge, the message should be same for both. Otherwise message should be different based on purpose.
enableSoftDelete_miss_err = "'Soft Delete' setting is currently not enabled for Key Vault" {
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
    not azure_attribute_absence["enablePurgeProtection"]
    not azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_issue["enablePurgeProtection"]
}

enablePurgeProtection = false {
    azure_attribute_absence["enablePurgeProtection"]
}


enablePurgeProtection_err = "Purge protection is currently not enabled on Key vault" {
    azure_issue["enableSoftDelete"]
}

# Rezoan: This rule is not being used. We should merge this rule with enablePurgeProtection_err in a OR logic. Farshid to confirm. 
# Consider this comment for each every rules that is similar to this one.
# if we merge, the message should be same for both. Otherwise message should be different based on purpose.
enablePurgeProtection_miss_err = "Purge protection is currently not enabled on Key vault" {
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