package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers

#

# PR-AZR-0128-ARM

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
    "Policy Code": "PR-AZR-0128-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers"
}






# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators

#

# PR-AZR-0133-ARM

default sql_server_login = null


azure_attribute_absence["sql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    resource.properties.login
}


azure_issue["sql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    lower(resource.properties.login) != "admin"
    lower(resource.properties.login) != "administrator"
}

sql_server_login {
    azure_attribute_absence["sql_server_login"]
    azure_issue["sql_server_login"]
}


sql_server_login = false {
    lower(input.resources[_].type) == "microsoft.sql/servers/administrators"
    not azure_attribute_absence["sql_server_login"]
}

sql_server_login = false {
    lower(input.resources[_].type) == "microsoft.sql/servers/administrators"
    not azure_issue["sql_server_login"]
}


sql_server_login_miss_err = "Azure SQL Server property 'login' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers/administrators"
    not azure_issue["sql_server_login"]
}

sql_server_login_err = "Azure SQL Server login is set to admin or administrator currently on the resource" {
    lower(input.resources[_].type) == "microsoft.sql/servers/administrators"
    not azure_issue["sql_server_login"]
}

sql_server_login_metadata := {
    "Policy Code": "PR-AZR-0133-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Avoid using names like 'Admin' for an Azure SQL Server admin account login",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators"
}
