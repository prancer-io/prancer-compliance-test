package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers

#
# Always use Private Endpoint for Azure SQL Database and SQL Managed Instance
#

default sql_public_access = null

azure_issue["sql_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

sql_public_access {
    lower(input.resources[_].type) == "microsoft.sql/servers"
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
    "Language": "ARM template",
    "Policy Title": "SQL servers with public access detected!",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Compliance": [],
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers"
}
