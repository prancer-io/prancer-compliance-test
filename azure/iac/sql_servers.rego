package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers

#

# PR-AZR-ARM-SQL-047

default sql_public_access_disabled = null

azure_attribute_absence["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.publicNetworkAccess
}

source_path[{"sql_public_access_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.publicNetworkAccess
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

azure_issue["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

source_path[{"sql_public_access_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
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
    "Policy Code": "PR-AZR-ARM-SQL-047",
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

# PR-AZR-ARM-SQL-048

default sql_server_login = null


azure_attribute_absence["sql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "administrators"
    not sql_resources.properties.login
}

source_path[{"sql_server_login":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "administrators"
    not sql_resources.properties.login
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","login"]]
    }
}

no_azure_issue["sql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "administrators"
    lower(sql_resources.properties.login) != "admin"
    lower(sql_resources.properties.login) != "administrator"
}

source_path[{"sql_server_login":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "administrators"
    lower(sql_resources.properties.login) != "admin"
    lower(sql_resources.properties.login) != "administrator"
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"properties","login"]]
    }
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
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "administrators"
    not no_azure_issue["sql_server_login"]
}

sql_server_login_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-048",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators"
}



# PR-AZR-ARM-SQL-049

default sql_logical_server_login = null


azure_attribute_absence["sql_logical_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    not resource.properties.login
}

source_path[{"sql_logical_server_login":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    not resource.properties.login
    metadata:= {
        "resource_path": [["resources",i,"properties","login"]]
    }
}

no_azure_issue["sql_logical_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    lower(resource.properties.login) != "admin"
    lower(resource.properties.login) != "administrator"
}

source_path[{"sql_logical_server_login":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    lower(resource.properties.login) != "admin"
    lower(resource.properties.login) != "administrator"
    metadata:= {
        "resource_path": [["resources",i,"properties","login"]]
    }
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
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers/administrators"
    not no_azure_issue["sql_logical_server_login"]
}

sql_logical_server_login_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-049",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "microsoft.sql/servers/administrators",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/administrators"
}





# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/failovergroups

# PR-AZR-ARM-SQL-050

default fail_over_groups = null

azure_issue["fail_over_groups"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "failovergroups"
}

source_path[{"fail_over_groups":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "failovergroups"
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"type"]]
    }
}


fail_over_groups {
	azure_issue["fail_over_groups"]
}


fail_over_groups = false {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    not azure_issue["fail_over_groups"]
}


fail_over_groups_err = "Microsoft.sql/servers resource property type.failoverGroups missing in the resource" {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    not azure_issue["fail_over_groups"]
}

fail_over_groups_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-050",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure SQL Server data replication with Fail Over groups",
    "Policy Description": "SQL Server data should be replicated to avoid loss of unreplicated data.",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/failovergroups"
}




# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/administrators

# PR-AZR-ARM-SQL-051

default sql_server_administrators = null


azure_attribute_absence["sql_server_administrators"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "administrators"
    not sql_resources.properties.administratorType
}

source_path[{"sql_server_administrators":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "administrators"
    not sql_resources.name
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"name"]]
    }
}

azure_issue["sql_server_administrators"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "administrators"
    lower(sql_resources.properties.administratorType) != "activedirectory"
}


source_path[{"sql_server_administrators":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[j]
    lower(sql_resources.type) == "administrators"
    lower(sql_resources.name) != "activedirectory"
    metadata:= {
        "resource_path": [["resources",i,"resources",j,"name"]]
    }
}

sql_server_administrators {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    sql_resources := resource.resources[_]
    lower(sql_resources.type) == "administrators"
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
    "Policy Code": "PR-AZR-ARM-SQL-051",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that Azure Active Directory Admin is configured for SQL Server",
    "Policy Description": "Use Azure Active Directory Authentication for authentication with SQL Databases. Azure Active Directory authentication is a mechanism of connecting Microsoft Azure SQL Databases and SQL Data Warehouses using identities in an Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location.",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers/administrators"
}
