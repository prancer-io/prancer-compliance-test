package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

#
# PR-AZR-ARM-SQL-078
#
default sql_db_backup_usage_locally_redundant_backup_storage = null

azure_attribute_absence["sql_db_backup_usage_locally_redundant_backup_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    not resource.properties.requestedBackupStorageRedundancy
}

azure_issue["sql_db_backup_usage_locally_redundant_backup_storage"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    lower(resource.properties.requestedBackupStorageRedundancy) != "local"
}

sql_db_backup_usage_locally_redundant_backup_storage {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases"
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
} else = "Azure SQL databases attribute 'requestedBackupStorageRedundancy' is missing from the resource. make sure to the value is set to 'Local'" {
    azure_attribute_absence["sql_db_backup_usage_locally_redundant_backup_storage"]
}

sql_db_backup_usage_locally_redundant_backup_storage_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-078",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Server Database backup storage redundancy should configure to use locally redundant backup storage",
    "Policy Description": "This policy will identify Azure SQL Server database which is not configured to use locally redundant backup storage for backup storage redundancy",
    "Resource Type": "microsoft.sql/servers/databases",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.sql/servers/databases?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.sql/servers/databases/backupshorttermretentionpolicies?pivots=deployment-language-arm-template

#
# PR-AZR-ARM-SQL-079
#

default sql_db_backup_restore_retention_config = null

azure_attribute_absence["sql_db_backup_restore_retention_config"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/databases/backupshorttermretentionpolicies"; c := 1]) == 0
}

azure_attribute_absence["sql_db_backup_restore_retention_config"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/backupshorttermretentionpolicies"
    not resource.dependsOn
}

azure_attribute_absence["sql_db_backup_restore_retention_config"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases/backupshorttermretentionpolicies"
    not resource.properties.retentionDays
}

azure_issue["sql_db_backup_restore_retention_config"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/databases"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/databases/backupshorttermretentionpolicies";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              to_number(r.properties.retentionDays) < 35;
              c := 1]) > 0
}

sql_db_backup_restore_retention_config {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases"
    not azure_attribute_absence["sql_db_backup_restore_retention_config"]
    not azure_issue["sql_db_backup_restore_retention_config"]
}

sql_db_backup_restore_retention_config = false {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases"
    azure_issue["sql_db_backup_restore_retention_config"]
}

sql_db_backup_restore_retention_config = false {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases"
    azure_attribute_absence["sql_db_backup_restore_retention_config"]
}

sql_db_backup_restore_retention_config_err = "Azure SQL Database Point in time restore retention configuration is not set for minimum 35 days" {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases"
    azure_issue["sql_db_backup_restore_retention_config"]
} else = "Azure SQL Database backupshorttermretentionpolicies attribute 'retentionDays' is missing" {
    lower(input.resources[_].type) == "microsoft.sql/servers/databases"
    azure_attribute_absence["sql_db_backup_restore_retention_config"]
}

sql_db_backup_restore_retention_config_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-079",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure SQL Server Database Point in time restore retention configuration should be set for minimum 35 days",
    "Policy Description": "This policy checks Azure SQL Databases whose Point in time restore retention configuration is not configured for minimum 35 days.",
    "Resource Type": "Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.sql/servers/databases/backupshorttermretentionpolicies?pivots=deployment-language-arm-template"
}