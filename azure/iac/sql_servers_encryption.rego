package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/encryptionprotector

# PR-AZR-ARM-SQL-046

default serverKeyType = null

azure_attribute_absence["serverKeyType"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/encryptionprotector"; c := 1]) == 0
}

azure_attribute_absence["serverKeyType"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/encryptionprotector"
    not resource.dependsOn
}

azure_attribute_absence["serverKeyType"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/encryptionprotector"
    not resource.properties.serverKeyType
}

azure_issue["serverKeyType"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/encryptionprotector";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.serverKeyType) == "azurekeyvault";
              c := 1]) == 0
}

# azure_issue["serverKeyType"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.sql/servers/encryptionprotector"
#     lower(resource.properties.serverKeyType) != "azurekeyvault"
# }

serverKeyType {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["serverKeyType"]
    not azure_issue["serverKeyType"]
}

serverKeyType = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["serverKeyType"]
}

serverKeyType = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["serverKeyType"]
}

serverKeyType_err = "SQL server's TDE protector is currently not encrypted with Customer-managed key." {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["serverKeyType"]
} else = "Azure SQL Server encryption protector settings property 'serverKeyType' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["serverKeyType"]
}

serverKeyType_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-046",
    "Type": "IaC",
    "Product": "",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL server's TDE protector is encrypted with Customer-managed key",
    "Policy Description": "Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.",
    "Resource Type": "microsoft.sql/servers/encryptionprotector",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/encryptionprotector"
}
