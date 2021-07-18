package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers

# PR-AZR-0115-ARM

default geoRedundantBackup = null

azure_attribute_absence["geoRedundantBackup"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.storageProfile.geoRedundantBackup
}

azure_issue["geoRedundantBackup"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.storageProfile.geoRedundantBackup) != "enabled"
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

geoRedundantBackup_err = "Ensure that Geo Redundant Backups is enabled on PostgreSQL" {
    azure_issue["geoRedundantBackup"]
}

geoRedundantBackup_miss_err = "Ensure that Geo Redundant Backups is enabled on PostgreSQL" {
    azure_attribute_absence["geoRedundantBackup"]
}

geoRedundantBackup_metadata := {
    "Policy Code": "PR-AZR-0115-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure that Geo Redundant Backups is enabled on PostgreSQL",
    "Policy Description": "Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers"
}





# PR-AZR-0124-ARM

default sslEnforcement = null
azure_attribute_absence ["sslEnforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.sslEnforcement
}

azure_issue ["sslEnforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.sslEnforcement) != "enabled"
}

sslEnforcement {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_issue["sslEnforcement"]
    not azure_attribute_absence["sslEnforcement"]
}

sslEnforcement = false {
    azure_issue["sslEnforcement"]
}

sslEnforcement = false {
    azure_attribute_absence["sslEnforcement"]
}


sslEnforcement_err = "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server" {
    azure_issue["sslEnforcement"]
}

sslEnforcement_miss_err = "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server" {
    azure_attribute_absence["sslEnforcement"]
}

sslEnforcement_metadata := {
    "Policy Code": "PR-AZR-0124-ARM",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server",
    "Policy Description": "Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers"
}