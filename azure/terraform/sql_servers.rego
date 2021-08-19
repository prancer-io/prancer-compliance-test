package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_mssql_server

#
# Always use Private Endpoint for Azure MSSQL Database and SQL Managed Instance (SQL MI resource is not available for terraform yet. 
# visit: https://github.com/hashicorp/terraform-provider-azurerm/issues/1747)
#

# PR-AZR-0126-TRF

default sql_public_access_disabled = null

azure_attribute_absence["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not resource.properties.public_network_access_enabled
}

azure_issue["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    resource.properties.public_network_access_enabled != false
}

sql_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["sql_public_access_disabled"]
    not azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled = false {
    azure_attribute_absence["sql_public_access_disabled"]
}

sql_public_access_disabled = false {
    azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled_err = "azurerm_mssql_server property 'public_network_access_enabled' need to be exist. Its missing from the resource. Please set the value to 'false' after property addition." {
    azure_attribute_absence["sql_public_access_disabled"]
} else = "Public Network Access is currently not disabled on MSSQL Server." {
    azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0126-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure SQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}

# https://docs.microsoft.com/en-us/azure/templates/azurerm_sql_server
# Always use Private Endpoint for Azure SQL Database and SQL Managed Instance
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server
# This resource provides usage of Microsoft SQL Azure Database server using an older sku based model. 
# It is recommended going forward to use azurerm_mssql_server resource which provides support for vcores.
# (code is kept for reference but not used anywhere)
default sql_public_access = null

azure_issue["sql_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

sql_public_access {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_issue["sql_public_access"]
}

sql_public_access = false {
    azure_issue["sql_public_access"]
}

sql_public_access_err = "SQL servers with public access detected!" {
    azure_issue["sql_public_access"]
}

sql_public_access_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "",
    "Language": "Terraform",
    "Policy Title": "SQL servers with public access detected!",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server"
}

