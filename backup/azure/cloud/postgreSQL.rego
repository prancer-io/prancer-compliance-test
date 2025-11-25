package rule

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers

# PR-AZR-CLD-SQL-028

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


azure_issue ["sslEnforcement"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.sslEnforcement) != "enabled"
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

azure_issue["postgresql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.publicNetworkAccess) != "disabled"
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


# https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers/firewallrules?pivots=deployment-language-arm-template
#
# PR-AZR-CLD-SQL-067
#

default pg_ingress_from_any_ip_disabled = null

azure_attribute_absence["pg_ingress_from_any_ip_disabled"] {
    count([c | lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers/firewallrules"; c := 1]) == 0
}

azure_issue["pg_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/firewallrules";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.startIpAddress == "0.0.0.0";
              c := 1]) > 0
}

azure_issue["pg_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/firewallrules";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.endIpAddress == "0.0.0.0";
              c := 1]) > 0
}

azure_issue["pg_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/firewallrules";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              r.properties.endIpAddress == "255.255.255.255";
              c := 1]) > 0
}

pg_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["pg_ingress_from_any_ip_disabled"]
    not azure_issue["pg_ingress_from_any_ip_disabled"]
}

pg_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["pg_ingress_from_any_ip_disabled"]
}

pg_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["pg_ingress_from_any_ip_disabled"]
    not azure_issue["pg_ingress_from_any_ip_disabled"]
}

pg_ingress_from_any_ip_disabled_err = "PostgreSQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["pg_ingress_from_any_ip_disabled"]
}

pg_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-067",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "PostgreSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify PostgreSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "microsoft.dbforpostgresql/servers/firewallrules",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers/firewallrules?pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-SQL-068

default postgresql_infrastructure_encryption_enabled = null

azure_attribute_absence["postgresql_infrastructure_encryption_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    not resource.properties.infrastructureEncryption
}

azure_issue["postgresql_infrastructure_encryption_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    lower(resource.properties.infrastructureEncryption) != "enabled"
}

postgresql_infrastructure_encryption_enabled {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["postgresql_infrastructure_encryption_enabled"]
    not azure_issue["postgresql_infrastructure_encryption_enabled"]
}

postgresql_infrastructure_encryption_enabled = false {
    azure_attribute_absence["postgresql_infrastructure_encryption_enabled"]
} 

postgresql_infrastructure_encryption_enabled = false {
    azure_issue["postgresql_infrastructure_encryption_enabled"]
}

postgresql_infrastructure_encryption_enabled_err = "Infrastructure double encryption is currently not enabled on PostgreSQL database Server." {
    azure_issue["postgresql_infrastructure_encryption_enabled"]
} else = "Property infrastructureEncryption is missing from resource of type 'Microsoft.DBforPostgreSQL/servers'" {
    azure_attribute_absence["postgresql_public_access_disabled"]
}

postgresql_infrastructure_encryption_enabled_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-068",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure PostgreSQL database server Infrastructure double encryption is enabled",
    "Policy Description": "This policy identifies PostgreSQL database servers in which Infrastructure double encryption is disabled. Infrastructure double encryption adds a second layer of encryption using service-managed keys. It is recommended to enable infrastructure double encryption on PostgreSQL database servers so that encryption can be implemented at the layer closest to the storage device or network wires. For more details: https://docs.microsoft.com/en-us/azure/postgresql/concepts-infrastructure-double-encryption",
    "Resource Type": "microsoft.dbforpostgresql/servers",
    "Policy Help URL": "",
    "Resource Help URL": "https://docs.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers"
}


# Help: https://docs.fugue.co/FG_R00337.html
# PR-AZR-CLD-SQL-070

default postgresql_log_retention_is_greater_than_three_days = null

azure_attribute_absence["postgresql_log_retention_is_greater_than_three_days"] {
    count([c | lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers/configurations"; c := 1]) == 0
}

azure_issue["postgresql_log_retention_is_greater_than_three_days"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/configurations";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.name) == "log_retention_days";
              to_number(r.properties.value) > 3;
              c := 1]) == 0
}

# azure_issue["postgresql_log_retention_is_greater_than_three_days"] {
#     resource := input.resources[_]
#     lower(resource.type) == "microsoft.dbforpostgresql/servers/configurations"
#     lower(resource.name) == "log_retention_days"
#     to_number(resource.properties.value) < 4
# }

postgresql_log_retention_is_greater_than_three_days {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["azurerm_postgresql_configuration_connection_throttling"]
    not azure_issue["postgresql_log_retention_is_greater_than_three_days"]
}

postgresql_log_retention_is_greater_than_three_days = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["postgresql_log_retention_is_greater_than_three_days"]
}

postgresql_log_retention_is_greater_than_three_days = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["postgresql_log_retention_is_greater_than_three_days"]
}

postgresql_log_retention_is_greater_than_three_days_err = "PostgreSQL database server log retention days is currently not greater than 3 days" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["postgresql_log_retention_is_greater_than_three_days"]
} else = "Either resource of type 'microsoft.dbforpostgresql/servers/configurations' or log_retention_days configuration from this resource is missing" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["postgresql_log_retention_is_greater_than_three_days"]
}

postgresql_log_retention_is_greater_than_three_days_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-070",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "Ensure PostgreSQL database server log retention days is greater than 3 days",
    "Policy Description": "This policy identifies PostgreSQL database servers which have log retention days less than or equals to 3 days. Enabling log_retention_days helps PostgreSQL database server to Sets number of days a log file is retained which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
    "Resource Type": "Microsoft.DBforPostgreSQL/servers/configurations",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers/configurations?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-SQL-071

default azurerm_postgresql_configuration_connection_throttling = null

azure_attribute_absence["azurerm_postgresql_configuration_connection_throttling"] {
    count([c | lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers/configurations"; c := 1]) == 0
}

azure_issue["azurerm_postgresql_configuration_connection_throttling"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/configurations";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.name) == "connection_throttling";
              lower(r.properties.value) == "on";
              c := 1]) == 0
}

azurerm_postgresql_configuration_connection_throttling {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["azurerm_postgresql_configuration_connection_throttling"]
    not azure_issue["azurerm_postgresql_configuration_connection_throttling"]
}

azurerm_postgresql_configuration_connection_throttling = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_connection_throttling"]
}

azurerm_postgresql_configuration_connection_throttling = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_connection_throttling"]
}

azurerm_postgresql_configuration_connection_throttling_err = "PostgreSQL database server connection throttling is currently not enabled" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_connection_throttling"]
} else = "Either resource of type 'microsoft.dbforpostgresql/servers/configurations' or connection_throttling configuration from this resource is missing" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_connection_throttling"]
}

azurerm_postgresql_configuration_connection_throttling_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-071",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "PostgreSQL Database Server should have connection_throttling enabled",
    "Policy Description": "This policy identifies PostgreSQL database servers for which server parameter is not set for connection throttling. Enabling connection_throttling helps the PostgreSQL Database to Set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
    "Resource Type": "Microsoft.DBforPostgreSQL/servers/configurations",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers/configurations?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-SQL-072

default azurerm_postgresql_configuration_log_checkpoints = null

azure_attribute_absence["azurerm_postgresql_configuration_log_checkpoints"] {
    count([c | lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers/configurations"; c := 1]) == 0
}

azure_issue["azurerm_postgresql_configuration_log_checkpoints"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/configurations";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.name) == "log_checkpoints";
              lower(r.properties.value) == "on";
              c := 1]) == 0
}

azurerm_postgresql_configuration_log_checkpoints {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["azurerm_postgresql_configuration_log_checkpoints"]
    not azure_issue["azurerm_postgresql_configuration_log_checkpoints"]
}

azurerm_postgresql_configuration_log_checkpoints = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_log_checkpoints"]
}

azurerm_postgresql_configuration_log_checkpoints = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_log_checkpoints"]
}

azurerm_postgresql_configuration_log_checkpoints_err = "PostgreSQL database server log checkpoints is currently not enabled" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_log_checkpoints"]
} else = "Either resource of type 'microsoft.dbforpostgresql/servers/configurations' or log_checkpoints parameter from this resource is missing" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_log_checkpoints"]
}

azurerm_postgresql_configuration_log_checkpoints_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-072",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "PostgreSQL Database Server should have log_checkpoints enabled",
    "Policy Description": "This policy identifies PostgreSQL database servers for which server parameter is not set for log checkpoints. Enabling log_checkpoints helps the PostgreSQL Database to Log each checkpoint in turn generates query and error logs. However, access to transaction logs is not supported. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
    "Resource Type": "Microsoft.DBforPostgreSQL/servers/configurations",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers/configurations?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-SQL-073

default azurerm_postgresql_configuration_log_connections = null

azure_attribute_absence["azurerm_postgresql_configuration_log_connections"] {
    count([c | lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers/configurations"; c := 1]) == 0
}

azure_issue["azurerm_postgresql_configuration_log_connections"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/configurations";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.name) == "log_connections";
              lower(r.properties.value) == "on";
              c := 1]) == 0
}

azurerm_postgresql_configuration_log_connections {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["azurerm_postgresql_configuration_log_connections"]
    not azure_issue["azurerm_postgresql_configuration_log_connections"]
}

azurerm_postgresql_configuration_log_connections = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_log_connections"]
}

azurerm_postgresql_configuration_log_connections = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_log_connections"]
}

azurerm_postgresql_configuration_log_connections_err = "PostgreSQL database server log connections parameter is currently not enabled" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_log_connections"]
} else = "Either resource of type 'microsoft.dbforpostgresql/servers/configurations' or log_connections parameter from this resource is missing" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_log_connections"]
}

azurerm_postgresql_configuration_log_connections_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-073",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "PostgreSQL Database Server should have log_connections parameter enabled",
    "Policy Description": "This policy identifies PostgreSQL database servers for which server parameter is not set for log connections. Enabling log_connections helps PostgreSQL Database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance.",
    "Resource Type": "Microsoft.DBforPostgreSQL/servers/configurations",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers/configurations?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-SQL-074

default azurerm_postgresql_configuration_log_disconnections = null

azure_attribute_absence["azurerm_postgresql_configuration_log_disconnections"] {
    count([c | lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers/configurations"; c := 1]) == 0
}

azure_issue["azurerm_postgresql_configuration_log_disconnections"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/configurations";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.name) == "log_disconnections";
              lower(r.properties.value) == "on";
              c := 1]) == 0
}

azurerm_postgresql_configuration_log_disconnections {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["azurerm_postgresql_configuration_log_disconnections"]
    not azure_issue["azurerm_postgresql_configuration_log_disconnections"]
}

azurerm_postgresql_configuration_log_disconnections = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_log_disconnections"]
}

azurerm_postgresql_configuration_log_disconnections = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_log_disconnections"]
}

azurerm_postgresql_configuration_log_disconnections_err = "PostgreSQL database server log disconnections parameter is currently not enabled" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_log_disconnections"]
} else = "Either resource of type 'microsoft.dbforpostgresql/servers/configurations' or log_disconnections parameter from this resource is missing" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_log_disconnections"]
}

azurerm_postgresql_configuration_log_disconnections_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-074",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "PostgreSQL Database Server should have log_disconnections parameter enabled",
    "Policy Description": "This policy identifies PostgreSQL database servers for which server parameter is not set for log disconnections. Enabling log_disconnections helps PostgreSQL Database to Logs end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
    "Resource Type": "Microsoft.DBforPostgreSQL/servers/configurations",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers/configurations?tabs=json&pivots=deployment-language-arm-template"
}


# PR-AZR-CLD-SQL-075

default azurerm_postgresql_configuration_log_duration = null

azure_attribute_absence["azurerm_postgresql_configuration_log_duration"] {
    count([c | lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers/configurations"; c := 1]) == 0
}

azure_issue["azurerm_postgresql_configuration_log_duration"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.dbforpostgresql/servers"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.dbforpostgresql/servers/configurations";
              #array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.name) == "log_duration";
              lower(r.properties.value) == "on";
              c := 1]) == 0
}

azurerm_postgresql_configuration_log_duration {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    not azure_attribute_absence["azurerm_postgresql_configuration_log_duration"]
    not azure_issue["azurerm_postgresql_configuration_log_duration"]
}

azurerm_postgresql_configuration_log_duration = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_log_duration"]
}

azurerm_postgresql_configuration_log_duration = false {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_log_duration"]
}

azurerm_postgresql_configuration_log_duration_err = "PostgreSQL database server log duration parameter is currently not enabled" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_issue["azurerm_postgresql_configuration_log_duration"]
} else = "Either resource of type 'microsoft.dbforpostgresql/servers/configurations' or log_duration parameter from this resource is missing" {
    lower(input.resources[_].type) == "microsoft.dbforpostgresql/servers"
    azure_attribute_absence["azurerm_postgresql_configuration_log_duration"]
}

azurerm_postgresql_configuration_log_duration_metadata := {
    "Policy Code": "PR-AZR-CLD-SQL-075",
    "Type": "Cloud",
    "Product": "AZR",
    "Language": "",
    "Policy Title": "PostgreSQL Database Server should have log_duration parameter enabled",
    "Policy Description": "This policy identifies PostgreSQL database servers for which server parameter is not set for log duration. Enabling log_duration helps the PostgreSQL Database to Logs the duration of each completed SQL statement which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance.",
    "Resource Type": "Microsoft.DBforPostgreSQL/servers/configurations",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.dbforpostgresql/servers/configurations?tabs=json&pivots=deployment-language-arm-template"
}