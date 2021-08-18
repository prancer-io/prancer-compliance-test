package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server

# PR-AZR-0115-TRF

default geoRedundantBackup = null

azure_attribute_absence["geoRedundantBackup"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_server"
    not resource.properties.geo_redundant_backup_enabled
}

azure_issue["geoRedundantBackup"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_server"
    resource.properties.geo_redundant_backup_enabled == false
}

geoRedundantBackup {
    lower(input.resources[_].type) == "azurerm_postgresql_server"
    not azure_attribute_absence["geoRedundantBackup"]
    not azure_issue["geoRedundantBackup"]
}

geoRedundantBackup = false {
    azure_attribute_absence["geoRedundantBackup"]
}

geoRedundantBackup = false {
    azure_issue["geoRedundantBackup"]
}

geoRedundantBackup_err "azurerm_postgresql_server property 'geo_redundant_backup_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["geoRedundantBackup"]
} else = "Geo-redundant backup is currently not enabled on PostgreSQL database server." {
    azure_issue["geoRedundantBackup"]
}

geoRedundantBackup_metadata := {
    "Policy Code": "PR-AZR-0115-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Geo-redundant backup is enabled on PostgreSQL database server.",
    "Policy Description": "Azure Database for PostgreSQL provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.",
    "Resource Type": "azurerm_postgresql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server"
}



# PR-AZR-0124-TRF

default sslEnforcement = null
azure_attribute_absence ["sslEnforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_server"
    not resource.properties.ssl_enforcement_enabled
}

azure_issue ["sslEnforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_server"
    resource.properties.ssl_enforcement_enabled == false
}

sslEnforcement {
    lower(input.resources[_].type) == "azurerm_postgresql_server"
    not azure_attribute_absence["sslEnforcement"]
    not azure_issue["sslEnforcement"]
}

sslEnforcement = false {
    azure_issue["sslEnforcement"]
}

sslEnforcement = false {
    azure_attribute_absence["sslEnforcement"]
}


sslEnforcement_err = "azurerm_postgresql_server property 'ssl_enforcement_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["sslEnforcement"]
} else = "Geo-redundant backup is currently not enabled on PostgreSQL database server." {
    azure_issue["sslEnforcement"]
}

sslEnforcement_metadata := {
    "Policy Code": "PR-AZR-0124-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure ssl enforcement is enabled on PostgreSQL Database Server.",
    "Policy Description": "Enable SSL connection on PostgreSQL Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
    "Resource Type": "azurerm_postgresql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server"
}