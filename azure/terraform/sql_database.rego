package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

#
# PR-AZR-TRF-SQL-078
#
default sql_db_backup_usage_locally_redundant_backup_storage = null

azure_attribute_absence["sql_db_backup_usage_locally_redundant_backup_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    not resource.properties.storage_account_type
}

azure_issue["sql_db_backup_usage_locally_redundant_backup_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    lower(resource.properties.storage_account_type) != "local"
}

sql_db_backup_usage_locally_redundant_backup_storage {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    not azure_attribute_absence["sql_db_backup_usage_locally_redundant_backup_storage"]
    not azure_issue["sql_db_backup_usage_locally_redundant_backup_storage"]
}

sql_db_backup_usage_locally_redundant_backup_storage = false {
    azure_issue["sql_db_backup_usage_locally_redundant_backup_storage"]
}

sql_db_backup_usage_locally_redundant_backup_storage = false {
    azure_attribute_absence["sql_db_backup_usage_locally_redundant_backup_storage"]
}

sql_db_backup_usage_locally_redundant_backup_storage_err = "Azure SQL databases backup currently not using locally redundant backup storage" {
    azure_issue["sql_db_backup_usage_locally_redundant_backup_storage"]
} else = "Azure SQL databases attribute 'storage_account_type' is missing from the resource. make sure to the value is set to 'Local'" {
    azure_attribute_absence["sql_db_backup_usage_locally_redundant_backup_storage"]
}

sql_db_backup_usage_locally_redundant_backup_storage_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-078",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server Database backup storage redundancy should configure to use locally redundant backup storage",
    "Policy Description": "This policy will identify Azure SQL Server database which is not configured to use locally redundant backup storage for backup storage redundancy",
    "Resource Type": "azurerm_mssql_database",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database"
}


#
# PR-AZR-TRF-SQL-079
#

default sql_db_backup_restore_retention_config = null

azure_attribute_absence["sql_db_backup_restore_retention_config"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    not resource.properties.short_term_retention_policy
}

azure_attribute_absence["sql_db_backup_restore_retention_config"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    short_term_retention_policy := resource.properties.short_term_retention_policy[_]
    not short_term_retention_policy.retention_days
}

azure_issue["sql_db_backup_restore_retention_config"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_database"
    short_term_retention_policy := resource.properties.short_term_retention_policy[_]
    to_number(short_term_retention_policy.retention_days) < 35
}

sql_db_backup_restore_retention_config {
    lower(input.resources[_].type) == "azurerm_mssql_database"
    not azure_attribute_absence["sql_db_backup_restore_retention_config"]
    not azure_issue["sql_db_backup_restore_retention_config"]
}

sql_db_backup_restore_retention_config = false {
    azure_issue["sql_db_backup_restore_retention_config"]
}

sql_db_backup_restore_retention_config = false {
    azure_attribute_absence["sql_db_backup_restore_retention_config"]
}

sql_db_backup_restore_retention_config_err = "Azure SQL Database Point in time restore retention configuration is not set for minimum 35 days" {
    azure_issue["sql_db_backup_restore_retention_config"]
} else = "Azure SQL Database attribute 'short_term_retention_policy.retention_days' is missing" {
    azure_attribute_absence["sql_db_backup_restore_retention_config"]
}

sql_db_backup_restore_retention_config_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-079",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server Database Point in time restore retention configuration should be set for minimum 35 days",
    "Policy Description": "This policy checks Azure SQL Databases whose Point in time restore retention configuration is not configured for minimum 35 days.",
    "Resource Type": "azurerm_mssql_database",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database"
}