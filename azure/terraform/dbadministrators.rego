package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_active_directory_administrator
#
# PR-AZR-0085-TRF
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
    count([c | input.resources[_].type == "azurerm_sql_server"; c := 1]) != count([c | input.resources[_].type == "azurerm_sql_active_directory_administrator"; c := 1])
}

db_ad_admin {
    #lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["db_ad_admin"]
    #not azure_issue["db_ad_admin"]
}

db_ad_admin = false {
    azure_attribute_absence["db_ad_admin"]
}

#db_ad_admin = false {
#    azure_issue["db_ad_admin"]
#}

db_ad_admin_err = "sql_active_directory_administrator resource is missing from template" {
    azure_attribute_absence["db_ad_admin"]
} #else = "SQL servers does not have Azure Active Directory admin configured" {
  #  azure_issue["db_ad_admin"]
#}

db_ad_admin_metadata := {
    "Policy Code": "PR-AZR-0085-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "SQL servers should be integrated with Azure Active Directory for administration",
    "Policy Description": "Checks to ensure that SQL servers are configured with Active Directory admin authentication. Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_active_directory_administrator"
}
