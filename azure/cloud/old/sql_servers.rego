package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers

#

# PR-AZR-SQL-047

default sql_public_access_disabled = null

azure_attribute_absence["sql_public_access_disabled"] {
    not input.properties.publicNetworkAccess
}


azure_issue["sql_public_access_disabled"] {
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
    "Policy Code": "PR-AZR-SQL-047",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure SQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers"
}


#

# PR-AZR-SQL-048

default sql_server_login = null


azure_attribute_absence["sql_server_login"] {
    sql_resources := input.resources[_]
    lower(sql_resources.type) == "administrators"
    not sql_resources.properties.login
}

no_azure_issue["sql_server_login"] {
    sql_resources := input.resources[_]
    lower(sql_resources.type) == "administrators"
    lower(sql_resources.properties.login) != "admin"
    lower(sql_resources.properties.login) != "administrator"
}

sql_server_login {
    not azure_attribute_absence["sql_server_login"]
    no_azure_issue["sql_server_login"]
}

sql_server_login = false {
    azure_attribute_absence["sql_server_login"]
}

sql_server_login = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "administrators"
    not no_azure_issue["sql_server_login"]
}

sql_server_login_err = "Azure SQL Server property 'login' is missing from the resource" {
    azure_attribute_absence["sql_server_login"]
} else = "Azure SQL Server login is currently set to admin or administrator on the resource. Please change the name" {
    sql_resources := input.resources[_]
    lower(sql_resources.type) == "administrators"
    not no_azure_issue["sql_server_login"]
}

sql_server_login_metadata := {
    "Policy Code": "PR-AZR-SQL-048",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators"
}


# PR-AZR-SQL-049

default sql_logical_server_login = null


azure_attribute_absence["sql_logical_server_login"] {
    not input.properties.administrators.login
}

no_azure_issue["sql_logical_server_login"] {
    lower(input.properties.administrators.login) != "admin"
    lower(input.properties.administrators.login) != "administrator"
}


sql_logical_server_login {
    not azure_attribute_absence["sql_logical_server_login"]
    no_azure_issue["sql_logical_server_login"]
}

sql_logical_server_login = false {
    azure_attribute_absence["sql_logical_server_login"]
}

sql_logical_server_login = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    not no_azure_issue["sql_logical_server_login"]
}

sql_logical_server_login_err = "Azure SQL Server property 'login' is missing from the resource" {
    azure_attribute_absence["sql_logical_server_login"]
} else = "Azure SQL Server login is currently set to admin or administrator on the resource. Please change the name" {
    not no_azure_issue["sql_logical_server_login"]
}

sql_logical_server_login_metadata := {
    "Policy Code": "PR-AZR-SQL-049",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators"
}


# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/failovergroups

# PR-AZR-SQL-050

default fail_over_groups = null

azure_issue["fail_over_groups"] {
    sql_resources := input.resources[_]
    lower(sql_resources.type) == "failovergroups"
}

fail_over_groups {
	azure_issue["fail_over_groups"]
}


fail_over_groups = false {
    not azure_issue["fail_over_groups"]
}


fail_over_groups_err = "Microsoft.sql/servers resource property type.failoverGroups missing in the resource" {
    not azure_issue["fail_over_groups"]
}

fail_over_groups_metadata := {
    "Policy Code": "PR-AZR-SQL-050",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure SQL Server data replication with Fail Over groups",
    "Policy Description": "SQL Server data should be replicated to avoid loss of unreplicated data.",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/failovergroups"
}






# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/administrators

# PR-AZR-SQL-051

default sql_server_administrators = null


azure_attribute_absence["sql_server_administrators"] {
    not input.properties.administrators.administratorType
}

azure_issue["sql_server_administrators"] {
    lower(input.properties.administrators.administratorType) != "activedirectory"
}

sql_server_administrators {
    not azure_attribute_absence["sql_server_administrators"]
    not azure_issue["sql_server_administrators"]
}


sql_server_administrators = false {
    azure_attribute_absence["sql_server_administrators"]
}

sql_server_administrators = false {
    azure_issue["sql_server_administrators"]
}

sql_server_administrators_err = "Microsoft.sql/servers/administrators resource property name missing in the resource" {
    azure_attribute_absence["sql_server_administrators"]
} else = "Azure Active Directory Admin is not configured for SQL Server" {
    azure_issue["sql_server_administrators"]
}

sql_server_administrators_metadata := {
    "Policy Code": "PR-AZR-SQL-051",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure that Azure Active Directory Admin is configured for SQL Server",
    "Policy Description": "Use Azure Active Directory Authentication for authentication with SQL Databases. Azure Active Directory authentication is a mechanism of connecting Microsoft Azure SQL Databases and SQL Data Warehouses using identities in an Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/administrators"
}



# PR-AZR-SQL-069
# Once minimum_tls_version is set it is not possible to remove this setting and must be given a valid value for any further updates to the resource.

default sql_server_latest_tls_configured = null

azure_attribute_absence["sql_server_latest_tls_configured"] {
    not input.properties.minimalTlsVersion
}

azure_issue["sql_server_latest_tls_configured"] {
    to_number(input.properties.minimalTlsVersion) != 1.2
}

sql_server_latest_tls_configured {
    not azure_attribute_absence["sql_server_latest_tls_configured"]
    not azure_issue["sql_server_latest_tls_configured"]
}

sql_server_latest_tls_configured = false {
    azure_attribute_absence["sql_server_latest_tls_configured"]
}

sql_server_latest_tls_configured = false {
    azure_issue["sql_server_latest_tls_configured"]
}

sql_server_latest_tls_configured_err = "Azure SQL Server currently dont have latest version of tls configured" {
    azure_issue["sql_server_latest_tls_configured"]
} else = "microsoft.sql/servers property 'minimalTlsVersion' need to be exist. Its missing from the resource. Please set the value to '1.2' after property addition." {
    azure_attribute_absence["sql_server_latest_tls_configured"]
}

sql_server_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-SQL-069",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Azure SQL Server has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure SQL Server which dont have latest version of tls configured and give alert",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers"
}