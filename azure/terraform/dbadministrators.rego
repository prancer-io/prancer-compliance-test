package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_active_directory_administrator
#
# PR-AZR-TRF-SQL-001
#

default db_ad_admin = null

#azure_attribute_absence["db_ad_admin"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_sql_server"
#    count([c | input.resources[_].type == "azurerm_sql_active_directory_administrator"; 
#           c := 1]) == 0
#}

#azure_issue["db_ad_admin"] {
#    resource := input.resources[_]
#    lower(resource.type) == "azurerm_sql_server"
#    count([c | r := input.resources[_];
#               r.type == "azurerm_sql_active_directory_administrator";
#               re_match(concat("", ["^.*\\.", resource.name, "\\..*$"]), r.properties.server_name); # Rezoan: this regex is not correct and need a fix. Snapshot file does not generate server_name out of the tf variable as well at r.properties.server_name
#               c := 1]) == 0
#    true == false # workaround for inconsistent resource naming (Note from Rezoan: need to investigate if this can be ignored/removed)
#}

azure_attribute_absence ["db_ad_admin"] {
    count([c | input.resources[_].type == "azurerm_sql_active_directory_administrator"; c := 1]) == 0
}

azure_issue["db_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_sql_active_directory_administrator";
              contains(r.properties.server_name, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_sql_active_directory_administrator";
              contains(r.properties.server_name, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
}

db_ad_admin {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["db_ad_admin"]
    not azure_issue["db_ad_admin"]
}

db_ad_admin = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["db_ad_admin"]
}

db_ad_admin = false {
   lower(input.resources[_].type) == "azurerm_sql_server"
   azure_issue["db_ad_admin"]
}

db_ad_admin_err = "sql_active_directory_administrator resource is missing from template or its not linked with target azurerm_sql_server" {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["db_ad_admin"]
} else = "SQL servers does not have Azure Active Directory admin configured" {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["db_ad_admin"]
}

db_ad_admin_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "SQL servers should be integrated with Azure Active Directory for administration",
    "Policy Description": "Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_active_directory_administrator"
}
