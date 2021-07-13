package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators

# PR-AZR-0117-ARM

default administratorLogin = null

azure_issue["administratorLogin"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.Sql/servers/administrators"
    lower(resource.properties.login) != "admin"
    lower(resource.properties.login) != "administrator"
}

administratorLogin {
    azure_issue["administratorLogin"]
}

administratorLogin = false {
    lower(input.resources[_].type) == "microsoft.Sql/servers/administrators"
    not azure_issue["administratorLogin"]
}

administratorLogin_err = "AVOID USING NAMES LIKE 'ADMIN' FOR AN AZURE SQL SERVER ADMIN ACCOUNT LOGIN" {
    lower(input.resources[_].type) == "microsoft.Sql/servers/administrators"
    not azure_issue["administratorLogin"]
}

administratorLogin_metadata := {
    "Policy Code": "PR-AZR-0117-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "AVOID USING NAMES LIKE 'ADMIN' FOR AN AZURE SQL SERVER ADMIN ACCOUNT LOGIN",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "microsoft.Sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators"
}

