package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_transparent_data_encryption

#
# PR-AZR-0084-TRF
#

default db_encrypt = null

azure_attribute_absence["db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    count([c | input.resources[_].type == "azurerm_mssql_server_transparent_data_encryption"; 
           c := 1]) == 0
}

azure_issue["db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    count([c | r := input.resources[_];
               r.type == "azurerm_mssql_server_transparent_data_encryption";
               count(r.properties.server_id) == 0;
               c := 1]) == 0
}

db_encrypt = false {
    azure_attribute_absence["db_encrypt"]
}

db_encrypt {
    lower(input.resources[_].type) == "azurerm_mssql_server_transparent_data_encryption"
    not azure_attribute_absence["db_encrypt"]
    not azure_issue["db_encrypt"]
}

db_encrypt = false {
    azure_issue["db_encrypt"]
}

db_encrypt_err = "azurerm_mssql_database dont have any associative azurerm_mssql_server_transparent_data_encryption resource" {
    azure_attribute_absence["db_encrypt"]
} else = "Azure SQL databases currently dont have transparent data encryption enabled" {
    azure_issue["db_encrypt"]
}

db_encrypt_metadata := {
    "Policy Code": "PR-AZR-0084-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL databases should have transparent data encryption enabled",
    "Policy Description": "Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchange log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.",
    "Resource Type": "azurerm_mssql_server_transparent_data_encryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_transparent_data_encryption"
}

