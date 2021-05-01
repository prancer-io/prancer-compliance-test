package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_sql_server

#
# Always use Private Endpoint for Azure SQL Database and SQL Managed Instance
#

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
