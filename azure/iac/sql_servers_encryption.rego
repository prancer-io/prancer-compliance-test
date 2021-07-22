package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/encryptionprotector

# PR-AZR-0111-ARM

default serverKeyType = null

azure_issue["serverKeyType"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/encryptionprotector"
    lower(resource.properties.serverKeyType) != "azurekeyvault"
}

serverKeyType {
    lower(input.resources[_].type) == "microsoft.sql/servers/encryptionprotector"
    not azure_issue["serverKeyType"]
}

serverKeyType = false {
    azure_issue["serverKeyType"]
}

serverKeyType_err = "Ensure SQL server's TDE protector is encrypted with Customer-managed key" {
    azure_issue["serverKeyType"]
}

serverKeyType_metadata := {
    "Policy Code": "PR-AZR-0111-ARM",
    "Type": "IaC",
    "Product": "",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL server's TDE protector is encrypted with Customer-managed key",
    "Policy Description": "Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.",
    "Resource Type": "microsoft.sql/servers/encryptionprotector",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/encryptionprotector"
}
