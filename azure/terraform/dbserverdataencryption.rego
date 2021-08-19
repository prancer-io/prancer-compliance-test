package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_transparent_data_encryption

#
# PR-AZR-0134-TRF
#
default db_server_encrypt = null

azure_attribute_absence["db_server_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    count([c | input.resources[_].type == "azurerm_mssql_server_transparent_data_encryption"; 
           c := 1]) == 0
}

azure_issue["db_server_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    count([c | r := input.resources[_];
               r.type == "azurerm_mssql_server_transparent_data_encryption";
               count(r.properties.server_id) == 0;
               c := 1]) == 0
}

db_server_encrypt = false {
    azure_attribute_absence["db_server_encrypt"]
}

db_server_encrypt {
    lower(input.resources[_].type) == "azurerm_mssql_server_transparent_data_encryption"
    not azure_attribute_absence["db_server_encrypt"]
    not azure_issue["db_server_encrypt"]
}

db_server_encrypt = false {
    azure_issue["db_server_encrypt"]
}

db_server_encrypt_err = "azurerm_mssql_server dont have any associative azurerm_mssql_server_transparent_data_encryption resource" {
    azure_attribute_absence["db_server_encrypt"]
} else = "Azure SQL Server currently dont have transparent data encryption enabled" {
    azure_issue["db_server_encrypt"]
}

db_server_encrypt_metadata := {
    "Policy Code": "PR-AZR-0134-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server should have transparent data encryption enabled",
    "Policy Description": "Transparent data encryption protects Azure SQL Server against malicious activity.",
    "Resource Type": "azurerm_mssql_server_transparent_data_encryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_transparent_data_encryption"
}

