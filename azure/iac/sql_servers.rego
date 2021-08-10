package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers

#

# PR-AZR-0126-ARM

default sql_public_access_disabled = null

azure_attribute_absence["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.publicNetworkAccess
}

azure_issue["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

sql_public_access_disabled {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_public_access_disabled"]
    not azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled = false {
    azure_attribute_absence["sql_public_access_disabled"]
}

sql_public_access_disabled = false {
    azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled_miss_err = "publicNetworkAccess property is missing from the resource." {
    azure_attribute_absence["sql_public_access_disabled"]
}

sql_public_access_disabled_err = "Public Network Access is currently not disabled on MSSQL Server" {
    azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0126-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers"
}
