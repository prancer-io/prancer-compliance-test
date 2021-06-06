package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances

#
# Always use Private Endpoint for Azure SQL Database and SQL Managed Instance
#

default sql_public_endpoint = null

azure_issue["sql_public_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/managedinstances"
    resource.properties.publicDataEndpointEnabled != false
}

sql_public_endpoint {
    lower(input.resources[_].type) == "microsoft.sql/managedinstances"
    not azure_issue["sql_public_endpoint"]
}

sql_public_endpoint = false {
    azure_issue["sql_public_endpoint"]
}

sql_public_endpoint_err = "SQL Managed Instance with enabled public endpoint detected!" {
    azure_issue["sql_public_endpoint"]
}

sql_public_endpoint_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "",
    "Language": "ARM template",
    "Policy Title": "SQL Managed Instance with enabled public endpoint detected!",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "microsoft.sql/managedinstances",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances"
}
