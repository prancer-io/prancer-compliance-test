package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers

# PR-AZR-ARM-SQL-016

default ssl_enforcement = null
azure_attribute_absence ["ssl_enforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    not resource.properties.sslEnforcement
}

source_path[{"ssl_enforcement":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbformysql/servers"
    not resource.properties.sslEnforcement
    metadata:= {
        "resource_path": [["resources",i,"properties","sslEnforcement"]]
    }
}

azure_issue ["ssl_enforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    lower(resource.properties.sslEnforcement) != "enabled"
}

source_path[{"ssl_enforcement":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbformysql/servers"
    lower(resource.properties.sslEnforcement) != "enabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","sslEnforcement"]]
    }
}

ssl_enforcement {
    lower(input.resources[_].type) == "microsoft.dbformysql/servers"
    not azure_attribute_absence["ssl_enforcement"]
    not azure_issue["ssl_enforcement"]
}

ssl_enforcement = false {
    azure_issue["ssl_enforcement"]
}

ssl_enforcement = false {
    azure_attribute_absence["ssl_enforcement"]
}


ssl_enforcement_err = "Either ssl enforcement is absent or disabled on MySQL server databases." {
    azure_attribute_absence["ssl_enforcement"]
} else = "Property ssl_enforcement of type enum is absent from resource of type microsoft.dbformysql/servers" {
    azure_issue["ssl_enforcement"]
}

ssl_enforcement_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-016",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure ssl enforcement is enabled on MySQL server Database Server.",
    "Policy Description": "Enable SSL connection on MySQL Servers databases. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
    "Resource Type": "microsoft.dbformysql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers"
}


# PR-AZR-ARM-SQL-060

default mysql_public_access_disabled = null

azure_attribute_absence["mysql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    not resource.properties.publicNetworkAccess 
}

source_path[{"mysql_public_access_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbformysql/servers"
    not resource.properties.publicNetworkAccess
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

azure_issue["mysql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

source_path[{"mysql_public_access_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbformysql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

mysql_public_access_disabled {
    azure_attribute_absence["mysql_public_access_disabled"]
} 

mysql_public_access_disabled {
    lower(input.resources[_].type) == "microsoft.dbformysql/servers"
    not azure_attribute_absence["mysql_public_access_disabled"]
    not azure_issue["mysql_public_access_disabled"]
}

mysql_public_access_disabled = false {
    azure_issue["mysql_public_access_disabled"]
}

mysql_public_access_disabled_err = "Public Network Access is currently not disabled on MySQL Server." {
    azure_issue["mysql_public_access_disabled"]
}

mysql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-060",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure MySQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure MySQL Database Server",
    "Resource Type": "microsoft.dbformysql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers"
}


# PR-AZR-ARM-SQL-061


default mysql_server_latest_tls_configured = null

#default to TLSEnforcementDisabled
azure_attribute_absence["mysql_server_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    not resource.properties.minimalTlsVersion
}

source_path[{"mysql_server_latest_tls_configured":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbformysql/servers"
    not resource.properties.minimalTlsVersion
    metadata:= {
        "resource_path": [["resources",i,"properties","minimalTlsVersion"]]
    }
}

azure_issue["mysql_server_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformysql/servers"
    lower(resource.properties.minimalTlsVersion) != "tls1_2"
}

source_path[{"mysql_server_latest_tls_configured":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbformysql/servers"
    lower(resource.properties.minimalTlsVersion) != "tls1_2"
    metadata:= {
        "resource_path": [["resources",i,"properties","minimalTlsVersion"]]
    }
}

mysql_server_latest_tls_configured {
    lower(input.resources[_].type) == "microsoft.dbformysql/servers"
    not azure_attribute_absence["mysql_server_latest_tls_configured"]
    not azure_issue["mysql_server_latest_tls_configured"]
}

mysql_server_latest_tls_configured = false {
    azure_attribute_absence["mysql_server_latest_tls_configured"]
}

mysql_server_latest_tls_configured = false {
    azure_issue["mysql_server_latest_tls_configured"]
}

mysql_server_latest_tls_configured_err = "Azure MySQL Server currently dont have latest version of tls configured" {
    azure_issue["mysql_server_latest_tls_configured"]
} else = "microsoft.dbformysql/servers property 'minimalTlsVersion' need to be exist. Its missing from the resource. Please set the value to 'TLS1_2' after property addition." {
    azure_attribute_absence["mysql_server_latest_tls_configured"]
}

storage_account_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-ARM-SQL-061",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure Azure MySQL Server has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure MySQL Server which doesn't have the latest version of tls configured and give the alert",
    "Resource Type": "microsoft.dbformysql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformysql/servers"
}