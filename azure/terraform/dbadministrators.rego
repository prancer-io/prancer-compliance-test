package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers/administrators

#
# PR-AZR-0085-TRF
#

default db_ad_admin = null

azure_attribute_absence["db_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    count([c | input.resources[_].type == "azurerm_sql_active_directory_administrator"; 
           c := 1]) == 0
}

azure_issue["db_ad_admin"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    count([c | r := input.resources[_];
               r.type == "azurerm_sql_active_directory_administrator";
               re_match(concat("", ["^.*\\.", resource.name, "\\..*$"]), r.properties.server_name);
               c := 1]) == 0
    true == false # workaround for inconsistent resource naming
}

db_ad_admin {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_issue["db_ad_admin"]
    not azure_attribute_absence["db_ad_admin"]
}

db_ad_admin = false {
    azure_issue["db_ad_admin"]
}

db_ad_admin = false {
    azure_attribute_absence["db_ad_admin"]
}

db_ad_admin_err = "SQL servers which do not have Azure Active Directory admin configured" {
    azure_issue["db_ad_admin"]
}

db_ad_admin_miss_err = "sql_active_directory_administrator resource missing in the resource" {
    azure_attribute_absence["db_ad_admin"]
}
