package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers

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
    "Policy Title": "Ensure SQL Server administrator login does not contain 'Admin/Administrator' as name",
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
    "Policy Title": "Ensure SQL Server administrator login does not contain 'Admin/Administrator' as name",
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



# PR-AZR-ARM-SQL-069
# Once minimum_tls_version is set it is not possible to remove this setting and must be given a valid value for any further updates to the resource.

default sql_server_latest_tls_configured = null

azure_attribute_absence["sql_server_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.minimalTlsVersion
}

source_path[{"sql_server_latest_tls_configured":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.minimalTlsVersion
    metadata:= {
        "resource_path": [["resources",i,"properties","minimalTlsVersion"]]
    }
}


azure_issue["sql_server_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    to_number(resource.properties.minimalTlsVersion) != 1.2
}

source_path[{"sql_server_latest_tls_configured":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    to_number(resource.properties.minimalTlsVersion) != 1.2
    metadata:= {
        "resource_path": [["resources",i,"properties","minimalTlsVersion"]]
    }
}

sql_server_latest_tls_configured {
    lower(input.resources[_].type) == "microsoft.sql/servers"
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
    "Policy Code": "PR-AZR-ARM-SQL-069",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure SQL Server has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure SQL Server which doesn't have the latest version of tls configured and give the alert",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers"
}

# PR-AZR-ARM-SQL-047

default sql_public_access = null


azure_attribute_absence["sql_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.publicNetworkAccess
}

source_path[{"sql_public_access":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    not resource.properties.publicNetworkAccess
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

azure_issue["sql_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.sql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

source_path[{"sql_public_access":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.sql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}


sql_public_access {
    azure_attribute_absence["sql_public_access"]
}

sql_public_access {
    lower(input.resources[_].type) == "microsoft.sql/servers"
    not azure_attribute_absence["sql_public_access"]
    not azure_issue["sql_public_access"]
}

sql_public_access = false {
    azure_issue["sql_public_access"]
}

sql_public_access_err = "SQL servers with public access detected!" {
    azure_issue["sql_public_access"]
}

sql_public_access_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-047",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "SQL servers with public access detected!",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "microsoft.sql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/servers"
}
