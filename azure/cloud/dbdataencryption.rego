package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption

#

# PR-AZR-SQL-008

default db_logical_encrypt = null

azure_attribute_absence["db_logical_encrypt"] {
    sql_db := input.resources[_]
    lower(sql_db.type) == "transparentdataencryption"
    not sql_db.properties.status
}

azure_issue["db_logical_encrypt"] {=
    sql_db := input.resources[_]
    lower(sql_db.type) == "transparentdataencryption"
    lower(sql_db.properties.status) != "enabled"
}

db_logical_encrypt {
    sql_db := input.resources[_]
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
    azure_issue["db_logical_encrypt"]
} else = "Azure SQL databases transparent encryption attribute 'status' is missing from the resource" {
    azure_attribute_absence["db_logical_encrypt"]
}

db_logical_encrypt_metadata := {
    "Policy Code": "PR-AZR-SQL-008",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL databases should have transparent data encryption enabled",
    "Policy Description": "Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchange log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.",
    "Resource Type": "microsoft.sql/servers/databases/transparentdataencryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption"
}


# PR-AZR-SQL-009


default db_encrypt = null

azure_attribute_absence["db_encrypt"] {
    not input.properties.status
}

azure_issue["db_encrypt"] {
    lower(input.properties.status) != "enabled"
}

db_encrypt {
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
} else = "Azure SQL databases transparent encryption attribute 'status' is missing from the resource" {
    azure_attribute_absence["db_encrypt"]
}

db_encrypt_metadata := {
    "Policy Code": "PR-AZR-SQL-009",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Azure SQL databases should have transparent data encryption enabled",
    "Policy Description": "Transparent data encryption protects Azure database against malicious activity. It performs real-time encryption and decryption of the database, related reinforcements, and exchange log records without requiring any changes to the application. It encrypts the storage of the entire database by using a symmetric key called the database encryption key.",
    "Resource Type": "microsoft.sql/servers/databases/transparentdataencryption",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/databases/transparentdataencryption"
}

