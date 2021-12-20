package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers

# PR-AZR-CLD-SQL-028

default geoRedundantBackup = null

azure_attribute_absence["geoRedundantBackup"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.storageProfile.geoRedundantBackup
}

source_path[{"geoRedundantBackup":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.storageProfile.geoRedundantBackup
    metadata:= {
        "resource_path": [["resources",i,"properties","storageProfile","geoRedundantBackup"]]
    }
}


azure_issue["geoRedundantBackup"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.storageProfile.geoRedundantBackup) != "enabled"
}


source_path[{"geoRedundantBackup":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.storageProfile.geoRedundantBackup) != "enabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","storageProfile","geoRedundantBackup"]]
    }
}


geoRedundantBackup {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["geoRedundantBackup"]
    not azure_issue["geoRedundantBackup"]
}

geoRedundantBackup = false {
    azure_attribute_absence["geoRedundantBackup"]
}

geoRedundantBackup = false {
    azure_issue["geoRedundantBackup"]
}

geoRedundantBackup_err = "Geo-redundant backup is currently not enabled on PostgreSQL database server." {
    azure_issue["geoRedundantBackup"]
}

geoRedundantBackup_miss_err = "Property geoRedundantBackup of type enum is absent from resource of type \"Microsoft.DBforPostgreSQL/servers\"" {
    azure_attribute_absence["geoRedundantBackup"]
}

geoRedundantBackup_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-028",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure Geo-redundant backup is enabled on PostgreSQL database server.",
    "Policy Description": "Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers"
}





# PR-AZR-CLD-SQL-029

default sslEnforcement = null

azure_attribute_absence ["sslEnforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.sslEnforcement
}

source_path[{"sslEnforcement":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.sslEnforcement
    metadata:= {
        "resource_path": [["resources",i,"properties","sslEnforcement"]]
    }
}

azure_issue ["sslEnforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.sslEnforcement) != "enabled"
}

source_path[{"sslEnforcement":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.sslEnforcement) != "enabled"
    metadata:= {
        "resource_path": [["resources",i,"properties","sslEnforcement"]]
    }
}

sslEnforcement {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["sslEnforcement"]
    not azure_issue["sslEnforcement"]
}

sslEnforcement = false {
    azure_issue["sslEnforcement"]
}

sslEnforcement = false {
    azure_attribute_absence["sslEnforcement"]
}


sslEnforcement_err = "Either ssl enforcement is absent or disabled on PostgreSQL Database Server." {
    azure_issue["sslEnforcement"]
}

sslEnforcement_miss_err = "Property sslEnforcement of type enum is absent from resource of type \"Microsoft.DBforPostgreSQL/servers\"" {
    azure_attribute_absence["sslEnforcement"]
}

sslEnforcement_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-029",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure ssl enforcement is enabled on PostgreSQL Database Server.",
    "Policy Description": "Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers"
}

# PR-AZR-CLD-SQL-066

default postgresql_public_access_disabled = null

azure_attribute_absence["postgresql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.publicNetworkAccess
}

source_path[{"postgresql_public_access_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.publicNetworkAccess
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

azure_issue["postgresql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

source_path[{"mairadb_public_access_disabled":metadata}] {
    resource := input.resources[i]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.publicNetworkAccess
    metadata:= {
        "resource_path": [["resources",i,"properties","publicNetworkAccess"]]
    }
}

postgresql_public_access_disabled {
    azure_attribute_absence["postgresql_public_access_disabled"]
} 

postgresql_public_access_disabled {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["postgresql_public_access_disabled"]
    not azure_issue["postgresql_public_access_disabled"]
}

postgresql_public_access_disabled = false {
    azure_issue["postgresql_public_access_disabled"]
}

postgresql_public_access_disabled_err = "Public Network Access is currently not disabled on PostgreSQL Server." {
    azure_issue["postgresql_public_access_disabled"]
}

postgresql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-066",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure PostgreSQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for PostgreSQL Server",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers"
}