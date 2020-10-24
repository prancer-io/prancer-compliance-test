package rule

# https://docs.microsoft.com/en-us/azure/templates/azurerm_mssql_server

#
# Always use Private Endpoint for Azure SQL Database and SQL Managed Instance
#

default sql_public_endpoint = null

azure_issue["sql_public_endpoint"] {
    resource := input.json.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    resource.properties.public_network_access_enabled != false
}

sql_public_endpoint {
    lower(input.json.resources[_].type) == "azurerm_mssql_server"
    not azure_issue["sql_public_endpoint"]
}

sql_public_endpoint = false {
    azure_issue["sql_public_endpoint"]
}

sql_public_endpoint_err = "SQL Managed Instance with enabled public endpoint detected!" {
    azure_issue["sql_public_endpoint"]
}
