package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances

# PR-AZR-ARM-SQL-041
#

default sql_mi_public_endpoint_disabled = null

azure_issue["sql_mi_public_endpoint_disabled"] {
    input.properties.publicDataEndpointEnabled == true
}

sql_mi_public_endpoint_disabled {
    not azure_issue["sql_mi_public_endpoint_disabled"]
}


sql_mi_public_endpoint_disabled = false {
    azure_issue["sql_mi_public_endpoint_disabled"]
}

sql_mi_public_endpoint_disabled_err = "SQL Managed Instance currently have public endpoint enabled. Please disable" {
    azure_issue["sql_mi_public_endpoint_disabled"]
}

sql_mi_public_endpoint_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-041",
    "Type": "IaC",
    "Product": "",
    "Language": "ARM template",
    "Policy Title": "SQL Managed Instance should have public endpoint access disabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "microsoft.sql/managedinstances",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/managedinstances"
}
