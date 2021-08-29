package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_transparent_data_encryption

#
# PR-AZR-0140-TRF
#
default db_server_encrypt = null

#azure_attribute_absence["db_server_encrypt"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_mssql_server"
#    count([c | input.resources[_].type == "azurerm_mssql_server_transparent_data_encryption"; 
#           c := 1]) == 0
#}

#azure_issue["db_server_encrypt"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_mssql_server"
#    count([c | r := input.resources[_];
#               r.type == "azurerm_mssql_server_transparent_data_encryption";
#               count(r.properties.server_id) == 0;
#               c := 1]) == 0
#}

azure_attribute_absence["db_server_encrypt"] {
    count([c | input.resources[_].type == "azurerm_mssql_server"; c := 1]) != count([c | input.resources[_].type == "azurerm_mssql_server_transparent_data_encryption"; c := 1])
}

db_server_encrypt = false {
    azure_attribute_absence["db_server_encrypt"]
}

db_server_encrypt {
#    lower(input.resources[_].type) == "azurerm_mssql_server_transparent_data_encryption"
    not azure_attribute_absence["db_server_encrypt"]
#    not azure_issue["db_server_encrypt"]
}

#db_server_encrypt = false {
#    azure_issue["db_server_encrypt"]
#}

db_server_encrypt_err = "azurerm_mssql_server dont have any associative azurerm_mssql_server_transparent_data_encryption resource" {
    azure_attribute_absence["db_server_encrypt"]
} #else = "Azure SQL Server currently dont have transparent data encryption enabled" {
  #  azure_issue["db_server_encrypt"]
#}

db_server_encrypt_metadata := {
    "Policy Code": "PR-AZR-0140-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server should have transparent data encryption enabled",
    "Policy Description": "Transparent data encryption protects Azure SQL Server against malicious activity.",
    "Resource Type": "azurerm_mssql_server_transparent_data_encryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_transparent_data_encryption"
}


# PR-AZR-0111-TRF

default serverKeyType = null

azure_attribute_absence["serverKeyType"] {
    count([c | input.resources[_].type == "azurerm_mssql_server"; c := 1]) != count([c | input.resources[_].type == "azurerm_mssql_server_transparent_data_encryption"; c := 1])
}

azure_attribute_absence["serverKeyType"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_transparent_data_encryption"
    not resource.properties.key_vault_key_id
}

azure_issue["serverKeyType"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server_transparent_data_encryption"
    count(resource.properties.key_vault_key_id) == 0
}

serverKeyType {
    lower(input.resources[_].type) == "azurerm_mssql_server_transparent_data_encryption"
    not azure_attribute_absence["serverKeyType"]
    not azure_issue["serverKeyType"]
}

serverKeyType = false {
    azure_attribute_absence["serverKeyType"]
}

serverKeyType = false {
    azure_issue["serverKeyType"]
}

serverKeyType_err = "Make sure resource azurerm_mssql_server and azurerm_mssql_server_transparent_data_encryption both exist and property 'key_vault_key_id' exist under azurerm_mssql_server_transparent_data_encryption as well." {
    azure_attribute_absence["serverKeyType"]
} else = "SQL server's TDE protector is currently not encrypted with Customer-managed key." {
    azure_issue["serverKeyType"]
}

serverKeyType_metadata := {
    "Policy Code": "PR-AZR-0111-TRF",
    "Type": "IaC",
    "Product": "",
    "Language": "Terraform",
    "Policy Title": "Ensure SQL server's TDE protector is encrypted with Customer-managed key",
    "Policy Description": "Customer-managed key support for Transparent Data Encryption (TDE) allows user control of TDE encryption keys and restricts who can access them and when. Azure Key Vault, Azure’s cloud-based external key management system is the first key management service where TDE has integrated support for Customer-managed keys. With Customer-managed key support, the database encryption key is protected by an asymmetric key stored in the Key Vault. The asymmetric key is set at the server level and inherited by all databases under that server.",
    "Resource Type": "azurerm_mssql_server_transparent_data_encryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_transparent_data_encryption"
}

