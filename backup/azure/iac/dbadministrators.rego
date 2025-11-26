package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators

#
# PR-AZR-ARM-SQL-001
#

default sql_server_ad_admin = null

azure_attribute_absence["sql_server_ad_admin"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/servers/administrators"; c := 1]) == 0
}

azure_attribute_absence["sql_server_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    not resource.dependsOn
}

azure_attribute_absence["sql_server_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    not resource.properties.administratorType
}

azure_issue["sql_server_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/servers/administrators";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.administratorType) == "activedirectory";
              c := 1]) == 0
}

azure_inner_attribute_absence ["sql_server_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.administrators
}

azure_inner_attribute_absence ["sql_server_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.administrators.administratorType
}

azure_inner_issue ["sql_server_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    lower(resource.properties.administrators.administratorType) != "activedirectory"
}

sql_server_ad_admin {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_server_ad_admin"]
    not azure_issue["sql_server_ad_admin"]
}

sql_server_ad_admin {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_inner_attribute_absence["sql_server_ad_admin"]
    not azure_inner_issue["sql_server_ad_admin"]
}

sql_server_ad_admin = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_ad_admin"]
    azure_inner_attribute_absence["sql_server_ad_admin"]
}

sql_server_ad_admin = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_ad_admin"]
    azure_inner_issue["sql_server_ad_admin"]
}

sql_server_ad_admin = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_inner_attribute_absence["sql_server_ad_admin"]
    azure_issue["sql_server_ad_admin"]
}

sql_server_ad_admin = false {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_ad_admin"]
    azure_inner_issue["sql_server_ad_admin"]
}

sql_server_ad_admin_err = "SQL servers currently does not have Azure Active Directory admin configured" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_issue["sql_server_ad_admin"]
    azure_inner_issue["sql_server_ad_admin"]
} else = "SQL servers administrators attribute administratorType is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_ad_admin"]
    azure_inner_attribute_absence["sql_server_ad_admin"]
} else = "SQL servers administrators attribute administratorType is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_inner_attribute_absence["sql_server_ad_admin"]
    azure_issue["sql_server_ad_admin"]
} else = "SQL servers administrators attribute administratorType is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    azure_attribute_absence["sql_server_ad_admin"]
    azure_inner_issue["sql_server_ad_admin"]
}

sql_server_ad_admin_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL servers should be integrated with Azure Active Directory for administration",
    "Policy Description": "Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators"
}


# PR-AZR-ARM-SQL-002
#

default sql_logical_server_ad_admin = null

azure_attribute_absence["sql_logical_server_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resource := resource.resources[_]
    lower(sql_resource.type) == "administrators"
    not sql_resource.properties.administratorType
}

source_path[{"sql_logical_server_ad_admin":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resource := resource.resources[j]
    lower(sql_resource.type) == "administrators"
    not sql_resource.properties.administratorType
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","administratorType"]]
    }
}

azure_issue["sql_logical_server_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resource := resource.resources[_]
    lower(sql_resource.type) == "administrators"
    lower(sql_resource.properties.administratorType) != "activedirectory"
}

source_path[{"sql_logical_server_ad_admin":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resource := resource.resources[j]
    lower(sql_resource.type) == "administrators"
    lower(sql_resource.properties.administratorType) != "activedirectory"
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","administratorType"]]
    }
}

sql_logical_server_ad_admin {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resource := resource.resources[_]
    lower(sql_resource.type) == "administrators"
    not azure_issue["sql_logical_server_ad_admin"]
    not azure_attribute_absence["sql_logical_server_ad_admin"]
}

sql_logical_server_ad_admin = false {
    azure_issue["sql_logical_server_ad_admin"]
}

sql_logical_server_ad_admin = false {
    azure_attribute_absence["sql_logical_server_ad_admin"]
}

sql_logical_server_ad_admin_err = "SQL servers currently does not have Azure Active Directory admin configured" {
    azure_attribute_absence["sql_logical_server_ad_admin"]
} else = "SQL servers currently does not have Azure Active Directory admin configured" {
    azure_issue["sql_logical_server_ad_admin"]
}

sql_logical_server_ad_admin_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL servers should be integrated with Azure Active Directory for administration",
    "Policy Description": "Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators"
}

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/administrators?tabs=json

#
# PR-AZR-ARM-SQL-003
#
# SQL Managed Instance is not available for Terraform yet. see: https://github.com/hashicorp/terraform-provider-azurerm/issues/1747

default sql_managedinstances_ad_admin = null

azure_attribute_absence["sql_managedinstances_ad_admin"] {
    count([c | lower(input.resources[_].type) == "microsoft.sql/managedinstances/administrators"; c := 1]) == 0
}

azure_attribute_absence["sql_managedinstances_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/administrators"
    not resource.dependsOn
}

azure_attribute_absence["sql_managedinstances_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances/administrators"
    not resource.properties.administratorType
}

azure_issue["sql_managedinstances_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.sql/managedinstances/administrators";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.administratorType) == "activedirectory";
              c := 1]) == 0
}

azure_inner_attribute_absence ["sql_managedinstances_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    not resource.properties.administrators
}

azure_inner_attribute_absence ["sql_managedinstances_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    not resource.properties.administrators.administratorType
}

azure_inner_issue ["sql_managedinstances_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    lower(resource.properties.administrators.administratorType) != "activedirectory"
}

sql_managedinstances_ad_admin {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    not azure_attribute_absence["sql_managedinstances_ad_admin"]
    not azure_issue["sql_managedinstances_ad_admin"]
}

sql_managedinstances_ad_admin {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    not azure_inner_attribute_absence["sql_managedinstances_ad_admin"]
    not azure_inner_issue["sql_managedinstances_ad_admin"]
}

sql_managedinstances_ad_admin = false {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_attribute_absence["sql_managedinstances_ad_admin"]
    azure_inner_attribute_absence["sql_managedinstances_ad_admin"]
}

sql_managedinstances_ad_admin = false {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_issue["sql_managedinstances_ad_admin"]
    azure_inner_issue["sql_managedinstances_ad_admin"]
}

sql_managedinstances_ad_admin = false {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_inner_attribute_absence["sql_managedinstances_ad_admin"]
    azure_issue["sql_managedinstances_ad_admin"]
}

sql_managedinstances_ad_admin = false {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_attribute_absence["sql_managedinstances_ad_admin"]
    azure_inner_issue["sql_managedinstances_ad_admin"]
}

sql_managedinstances_ad_admin_err = "SQL managedinstances currently does not have Azure Active Directory admin configured" {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_issue["sql_managedinstances_ad_admin"]
    azure_inner_issue["sql_managedinstances_ad_admin"]
} else = "SQL managedinstances administrators attribute administratorType is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_attribute_absence["sql_managedinstances_ad_admin"]
    azure_inner_attribute_absence["sql_managedinstances_ad_admin"]
} else = "SQL managedinstances administrators attribute administratorType is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_inner_attribute_absence["sql_managedinstances_ad_admin"]
    azure_issue["sql_managedinstances_ad_admin"]
} else = "SQL managedinstances administrators attribute administratorType is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    azure_attribute_absence["sql_managedinstances_ad_admin"]
    azure_inner_issue["sql_managedinstances_ad_admin"]
}

sql_managedinstances_ad_admin_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL managedInstances should be integrated with Azure Active Directory for administration",
    "Policy Description": "Checks to ensure that SQL managedInstances are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "microsoft.sql/managedInstances/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances/administrators?tabs=json"
}
