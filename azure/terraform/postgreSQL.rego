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

geoRedundantBackup_err = "azurerm_postgresql_server property 'geo_redundant_backup_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
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


# PR-AZR-0146-TRF

default pg_ingress_from_any_ip_disabled = null

azure_attribute_absence ["pg_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_postgresql_server"; c := 1]) != count([c | input.resources[_].type == "azurerm_postgresql_firewall_rule"; c := 1])
}

azure_attribute_absence ["pg_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_firewall_rule"
    not resource.properties.start_ip_address
}

azure_attribute_absence ["pg_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_firewall_rule"
    not resource.properties.end_ip_address
}

azure_issue ["pg_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_firewall_rule"
    contains(resource.properties.start_ip_address, "0.0.0.0")
}

azure_issue ["pg_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_firewall_rule"
    contains(resource.properties.end_ip_address, "0.0.0.0")
}

pg_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_postgresql_firewall_rule"
    not azure_attribute_absence["pg_ingress_from_any_ip_disabled"]
    not azure_issue["pg_ingress_from_any_ip_disabled"]
}

pg_ingress_from_any_ip_disabled = false {
    azure_issue["pg_ingress_from_any_ip_disabled"]
}

pg_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["pg_ingress_from_any_ip_disabled"]
}

pg_ingress_from_any_ip_disabled_err = "Resource azurerm_postgresql_server and azurerm_postgresql_firewall_rule need to be exist and property 'start_ip_address' and 'end_ip_address' need to be exist under azurerm_postgresql_firewall_rule as well. one or all are missing from the resource." {
    azure_attribute_absence["pg_ingress_from_any_ip_disabled"]
} else = "PostgreSQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["pg_ingress_from_any_ip_disabled"]
}

pg_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-0146-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "PostgreSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify PostgreSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "azurerm_postgresql_firewall_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_firewall_rule"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration
# PR-AZR-0185-TRF

default azurerm_postgresql_configuration_log_checkpoints = null
azure_issue ["azurerm_postgresql_configuration_log_checkpoints"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_configuration"
    lower(resource.properties.name) == "log_checkpoints"
    lower(resource.properties.value) == "off"
}

azurerm_postgresql_configuration_log_checkpoints {
    lower(input.resources[_].type) == "azurerm_postgresql_configuration"
    not azure_issue["azurerm_postgresql_configuration_log_checkpoints"]
}

azurerm_postgresql_configuration_log_checkpoints = false {
    azure_issue["azurerm_postgresql_configuration_log_checkpoints"]
}

azurerm_postgresql_configuration_log_checkpoints_err = "log_checkpoints is currently not enabled on PostgreSQL database server." {
    azure_issue["azurerm_postgresql_configuration_log_checkpoints"]
}

azurerm_postgresql_configuration_log_checkpoints_metadata := {
    "Policy Code": "PR-AZR-0185-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "PostgreSQL Database Server should have log_checkpoints enabled",
    "Policy Description": "A checkpoint is a point in the transaction log sequence at which all data files have been updated to reflect the information in the log. All data files will be flushed to disk. Refer to Section 29.4 for more details about what happens during a checkpoint. this policy will identify Postgresql DB Server which dont have checkpoint log enabled and alert.",
    "Resource Type": "azurerm_postgresql_configuration",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration
# PR-AZR-0186-TRF

default azurerm_postgresql_configuration_log_connections = null
azure_issue ["azurerm_postgresql_configuration_log_connections"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_configuration"
    lower(resource.properties.name) == "log_connections"
    lower(resource.properties.value) == "off"
}

azurerm_postgresql_configuration_log_connections {
    lower(input.resources[_].type) == "azurerm_postgresql_configuration"
    not azure_issue["azurerm_postgresql_configuration_log_connections"]
}

azurerm_postgresql_configuration_log_connections = false {
    azure_issue["azurerm_postgresql_configuration_log_connections"]
}

azurerm_postgresql_configuration_log_connections_err = "log_connections is currently not enabled on PostgreSQL database server." {
    azure_issue["azurerm_postgresql_configuration_log_connections"]
}

azurerm_postgresql_configuration_log_connections_metadata := {
    "Policy Code": "PR-AZR-0186-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "PostgreSQL Database Server should have log_connections enabled",
    "Policy Description": "Causes each attempted connection to the server to be logged, as well as successful completion of client authentication. Only superusers can change this parameter at session start, and it cannot be changed at all within a session. this policy will identify Postgresql DB Server which dont have log_connections enabled and alert.",
    "Resource Type": "azurerm_postgresql_configuration",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration
# PR-AZR-0187-TRF

default azurerm_postgresql_configuration_connection_throttling = null
azure_issue ["azurerm_postgresql_configuration_connection_throttling"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_postgresql_configuration"
    lower(resource.properties.name) == "connection_throttling"
    lower(resource.properties.value) == "off"
}

azurerm_postgresql_configuration_connection_throttling {
    lower(input.resources[_].type) == "azurerm_postgresql_configuration"
    not azure_issue["azurerm_postgresql_configuration_connection_throttling"]
}

azurerm_postgresql_configuration_connection_throttling = false {
    azure_issue["azurerm_postgresql_configuration_connection_throttling"]
}

azurerm_postgresql_configuration_connection_throttling_err = "connection_throttling is currently not enabled on PostgreSQL database server." {
    azure_issue["azurerm_postgresql_configuration_connection_throttling"]
}

azurerm_postgresql_configuration_connection_throttling_metadata := {
    "Policy Code": "PR-AZR-0187-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "PostgreSQL Database Server should have connection_throttling enabled",
    "Policy Description": "Enabling connection_throttling allows the PostgreSQL Database to set the verbosity of logged messages which in turn generates query and error logs with respect to concurrent connections, that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources.",
    "Resource Type": "azurerm_postgresql_configuration",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration"
}