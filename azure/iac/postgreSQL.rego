package rule

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/2017-12-01/servers

# PR-AZR-0115-ARM

default geoRedundantBackup = null

azure_issue["geoRedundantBackup"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.storageProfile.geoRedundantBackup) != "Enabled"
}

geoRedundantBackup {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_issue["geoRedundantBackup"]
}

geoRedundantBackup = false {
    azure_issue["geoRedundantBackup"]
}

geoRedundantBackup_err = "ENSURE THAT GEO REDUNDANT BACKUPS IS ENABLED ON POSTGRESQL" {
    azure_issue["geoRedundantBackup"]
}

geoRedundantBackup_metadata := {
    "Policy Code": "PR-AZR-0115-ARM",
    "Type": "IaC",
    "Product": "",
    "Language": "ARM template",
    "Policy Title": "ENSURE THAT GEO REDUNDANT BACKUPS IS ENABLED ON POSTGRESQL",
    "Policy Description": "Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/2017-12-01/servers"
}
