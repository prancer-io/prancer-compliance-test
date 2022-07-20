package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/2018-06-01/servers/firewallrules

# PR-AZR-CLD-SQL-012

default maria_ingress_from_any_ip_disabled = null
azure_attribute_absence ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers/firewallrules"
    not resource.properties.startIpAddress
}

azure_attribute_absence ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers/firewallrules"
    not resource.properties.endIpAddress
}

azure_issue ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers/firewallrules"
    contains(resource.properties.startIpAddress, "0.0.0.0")
}

azure_issue ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers/firewallrules"
    contains(resource.properties.endIpAddress, "0.0.0.0")
}


maria_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "microsoft.dbformariadb/servers/firewallrules"
    not azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
    not azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled = false {
    azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
}


maria_ingress_from_any_ip_disabled_err = "microsoft.dbformariadb/servers/firewallRules property 'startIpAddress' and 'endIpAddress' need to be exist. one or both are missing from the resource." {
    azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
} else = "MariaDB currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-012",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MariaDB firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "microsoft.dbformariadb/servers/firewallrules",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/2018-06-01/servers/firewallrules"
}




# PR-AZR-CLD-SQL-013
# Not valid for cloud provider as cloud seperates all the child resources into seperate resource

# default dbmaria_ingress_from_any_ip_disabled = null
# azure_attribute_absence ["dbmaria_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.dbformariadb/servers"
#     dbsql_resources := resource.resources[_]
#     lower(dbsql_resources.type) == "firewallrules"
#     not dbsql_resources.properties.startIpAddress
# }


# azure_attribute_absence ["dbmaria_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.dbformariadb/servers"
#     dbsql_resources := resource.resources[_]
#     lower(dbsql_resources.type) == "firewallrules"
#     not dbsql_resources.properties.endIpAddress
# }


# azure_issue ["dbmaria_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.dbformariadb/servers"
#     dbsql_resources := resource.resources[_]
#     lower(dbsql_resources.type) == "firewallrules"
#     contains(dbsql_resources.properties.startIpAddress, "0.0.0.0")
# }

# azure_issue ["dbmaria_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.dbformariadb/servers"
#     dbsql_resources := resource.resources[_]
#     lower(dbsql_resources.type) == "firewallrules"
#     contains(dbsql_resources.properties.endIpAddress, "0.0.0.0")
# }


# dbmaria_ingress_from_any_ip_disabled {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.dbformariadb/servers"
#     dbsql_resources := resource.resources[_]
#     lower(dbsql_resources.type) == "firewallrules"
#     not azure_attribute_absence["dbmaria_ingress_from_any_ip_disabled"]
#     not azure_issue["dbmaria_ingress_from_any_ip_disabled"]
# }

# dbmaria_ingress_from_any_ip_disabled = false {
#     azure_issue["dbmaria_ingress_from_any_ip_disabled"]
# }

# dbmaria_ingress_from_any_ip_disabled = false {
#     azure_attribute_absence["dbmaria_ingress_from_any_ip_disabled"]
# }


# dbmaria_ingress_from_any_ip_disabled_err = "microsoft.dbformariadb/servers/firewallrules property 'startIpAddress' and 'endIpAddress' need to be exist. one or both are missing from the resource." {
#     azure_attribute_absence["dbmaria_ingress_from_any_ip_disabled"]
# } else = "MariaDB currently allowing ingress from all Azure-internal IP addresses" {
#     azure_issue["dbmaria_ingress_from_any_ip_disabled"]
# }

# dbmaria_ingress_from_any_ip_disabled_metadata := {
#     "Policy Code": "PR-AZR-CLD-SQL-013",
#     "Type": "Cloud",
#     "Product": "AZR",
#     "Language": "",
#     "Policy Title": "MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
#     "Policy Description": "This policy will identify MariaDB firewall rule that is currently allowing ingress from all Azure-internal IP addresses",
#     "Resource Type": "microsoft.dbformariadb/servers/firewallrules",
#     "Policy Help URL": "",
#     "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/servers/firewallrules"
# }



# PR-AZR-CLD-SQL-056

default mairadb_ssl_enforcement_enabled = null
azure_attribute_absence ["mairadb_ssl_enforcement_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    not resource.properties.sslEnforcement
}

azure_issue ["mairadb_ssl_enforcement_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    lower(resource.properties.sslEnforcement) != "enabled"
}

mairadb_ssl_enforcement_enabled {
    lower(input.resources[_].type) == "microsoft.dbformariadb/servers"
    not azure_attribute_absence["mairadb_ssl_enforcement_enabled"]
    not azure_issue["mairadb_ssl_enforcement_enabled"]
}

mairadb_ssl_enforcement_enabled = false {
    azure_issue["mairadb_ssl_enforcement_enabled"]
}

mairadb_ssl_enforcement_enabled = false {
    azure_attribute_absence["mairadb_ssl_enforcement_enabled"]
}


mairadb_ssl_enforcement_enabled_err = "ssl enforcement is currently not enabled on MariaDB server." {
    azure_issue["mairadb_ssl_enforcement_enabled"]
} else = "microsoft.dbformariadb/servers property 'sslEnforcement' need to be exist. Its missing from the resource. Please set the value to 'enabled' after property addition." {
    azure_attribute_absence["mairadb_ssl_enforcement_enabled"]
}

mairadb_ssl_enforcement_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-056",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure ssl enforcement is enabled on MariaDB Server.",
    "Policy Description": "Enable SSL connection on MariaDB Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
    "Resource Type": "microsoft.dbformariadb/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/servers"
}


# PR-AZR-CLD-SQL-057

default mairadb_public_access_disabled = null


azure_attribute_absence["mairadb_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    not resource.properties.publicNetworkAccess
}


azure_issue["mairadb_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

mairadb_public_access_disabled {
    azure_attribute_absence["mairadb_public_access_disabled"]
} 

mairadb_public_access_disabled {
    lower(input.resources[_].type) == "microsoft.dbformariadb/servers"
    not azure_attribute_absence["mairadb_public_access_disabled"]
    not azure_issue["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled = false {
    azure_issue["mairadb_public_access_disabled"]
}



mairadb_public_access_disabled_err = "Public Network Access is currently not disabled on MariaDB Server." {
    azure_issue["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-057",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure MariaDB servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for MariaDB Server",
    "Resource Type": "microsoft.dbformariadb/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/servers"
}


# PR-AZR-CLD-SQL-058

default mariadb_geo_redundant_backup_enabled = null

azure_attribute_absence["mariadb_geo_redundant_backup_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    not resource.properties.storageProfile.geoRedundantBackup
}

azure_issue["mariadb_geo_redundant_backup_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    lower(resource.properties.storageProfile.geoRedundantBackup) != "enabled"
}


mariadb_geo_redundant_backup_enabled {
    lower(input.resources[_].type) == "microsoft.dbformariadb/servers"
    not azure_attribute_absence["mariadb_geo_redundant_backup_enabled"]
    not azure_issue["mariadb_geo_redundant_backup_enabled"]
}

mariadb_geo_redundant_backup_enabled = false {
    azure_attribute_absence["mariadb_geo_redundant_backup_enabled"]
}

mariadb_geo_redundant_backup_enabled = false {
    azure_issue["mariadb_geo_redundant_backup_enabled"]
}


mariadb_geo_redundant_backup_enabled_err = "Geo-redundant backup is currently not enabled on MariaDB server." {
    azure_issue["mariadb_geo_redundant_backup_enabled"]
} else = "microsoft.dbformariadb/servers property 'geoRedundantBackup' need to be exist. Its missing from the resource. Please set the value to 'enabled' after property addition." {
    azure_attribute_absence["mariadb_geo_redundant_backup_enabled"]
}

mariadb_geo_redundant_backup_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-058",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Geo-redundant backup is enabled on MariaDB server.",
    "Policy Description": "Azure Database for MariaDB provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.",
    "Resource Type": "microsoft.dbformariadb/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/servers"
}


# PR-AZR-CLD-SQL-064

default mairadb_usage_latest_tls = null

azure_attribute_absence ["mairadb_usage_latest_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    not resource.properties.minimalTlsVersion
}

azure_issue ["mairadb_usage_latest_tls"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbformariadb/servers"
    lower(resource.properties.minimalTlsVersion) != "tls1_2"
}

mairadb_usage_latest_tls {
    lower(input.resources[_].type) == "microsoft.dbformariadb/servers"
    not azure_attribute_absence["mairadb_usage_latest_tls"]
    not azure_issue["mairadb_usage_latest_tls"]
}

mairadb_usage_latest_tls = false {
    azure_issue["mairadb_usage_latest_tls"]
}

mairadb_usage_latest_tls = false {
    azure_attribute_absence["mairadb_usage_latest_tls"]
}

mairadb_usage_latest_tls_err = "MariaDB server currently not using latest TLS version." {
    azure_issue["mairadb_usage_latest_tls"]
} else = "microsoft.dbformariadb/servers property 'minimalTlsVersion' need to be exist. Its missing from the resource. Please set the value to 'TLS1_2' after property addition." {
    azure_attribute_absence["mairadb_usage_latest_tls"]
}

mairadb_usage_latest_tls_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-064",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure MariaDB Server is using latest TLS version.",
    "Policy Description": "This policy identifies Azure MariaDB database servers that are not using the latest TLS version for SSL enforcement. Azure Database for MariaDB uses Transport Layer Security (TLS) from communication with client applications. As a best security practice, use the newer TLS version as the minimum TLS version for the MariaDB database server. Currently, Azure MariaDB supports TLS 1.2 version which resolves the security gap from its preceding versions.",
    "Resource Type": "microsoft.dbformariadb/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbformariadb/servers"
}
