package rule

# https://docs.microsoft.com/en-us/rest/api/sql/2021-02-01-preview/encryption-protectors/get

# PR-AZR-SQL-046

default serverKeyType = null

azure_attribute_absence["serverKeyType"] {
    not input.properties.serverKeyType
}

azure_issue["serverKeyType"] {
    lower(input.properties.serverKeyType) != "azurekeyvault"
}

serverKeyType {
    not azure_attribute_absence["serverKeyType"]
    not azure_issue["serverKeyType"]
}

serverKeyType = false {
    azure_attribute_absence["serverKeyType"]
}

serverKeyType = false {
    azure_issue["serverKeyType"]
}

serverKeyType_err = "SQL server's TDE protector is currently not encrypted with Customer-managed key." {
    azure_issue["serverKeyType"]
}

serverKeyType_metadata := {
    "Policy Code": "PR-AZR-SQL-046",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure SQL server's TDE protector is encrypted with Customer-managed key",
    "Policy Description": "Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.",
    "Resource Type": "microsoft.sql/servers/encryptionprotector",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/rest/api/sql/2021-02-01-preview/encryption-protectors/get"
}
