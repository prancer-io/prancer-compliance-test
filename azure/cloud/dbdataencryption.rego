package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption

#

# PR-AZR-CLD-SQL-008

default db_logical_encrypt = null

azure_attribute_absence["db_logical_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "transparentdataencryption"
    not sql_db.properties.status
}

azure_issue["db_logical_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "transparentdataencryption"
    lower(sql_db.properties.status) != "enabled"
}


db_logical_encrypt {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    sql_db := resource.resources[_]
    lower(sql_db.type) == "transparentdataencryption"
    not azure_attribute_absence["db_logical_encrypt"]
    not azure_issue["db_logical_encrypt"]
}

db_logical_encrypt = false {
    azure_issue["db_logical_encrypt"]
}

db_logical_encrypt = false {
    azure_attribute_absence["db_logical_encrypt"]
}

db_logical_encrypt_err = "Azure SQL databases currently dont have transparent data encryption enabled" {
    azure_attribute_absence["db_logical_encrypt"]
} else = "Azure SQL databases currently dont have transparent data encryption enabled" {
    azure_issue["db_logical_encrypt"]
}

db_logical_encrypt_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL databases should have transparent data encryption enabled",
    "Policy Description": "Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchanges log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.",
    "Resource Type": "microsoft.sql/servers/databases/transparentdataencryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption"
}


# PR-AZR-CLD-SQL-009
#
# This encryption is by default enabled for sql database. Thats why its not available in Terraform.
# See https://github.com/hashicorp/terraform-provider-azurerm/issues/7187
# ToDo: We need to make sure its enabled for MSSQL Server
default db_encrypt = null

azure_attribute_absence["db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/transparentdataencryption"
    not resource.properties.status
}

azure_issue["db_encrypt"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/transparentdataencryption"
    lower(resource.properties.status) != "enabled"
}


db_encrypt {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases/transparentdataencryption"
    not azure_attribute_absence["db_encrypt"]
    not azure_issue["db_encrypt"]
}

db_encrypt = false {
    azure_issue["db_encrypt"]
}

db_encrypt = false {
    azure_attribute_absence["db_encrypt"]
}

db_encrypt_err = "Azure SQL databases currently dont have transparent data encryption enabled" {
    azure_issue["db_encrypt"]
}

db_encrypt_miss_err = "Azure SQL databases transparent encryption attribute 'status' is missing from the resource" {
    azure_attribute_absence["db_encrypt"]
}

db_encrypt_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL databases should have transparent data encryption enabled",
    "Policy Description": "Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchanges log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.",
    "Resource Type": "microsoft.sql/servers/databases/transparentdataencryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption"
}

