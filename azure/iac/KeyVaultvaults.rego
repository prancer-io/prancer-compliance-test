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