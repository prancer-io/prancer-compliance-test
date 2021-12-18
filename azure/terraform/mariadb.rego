package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_firewall_rule

# PR-AZR-TRF-SQL-012

default maria_ingress_from_any_ip_disabled = null

azure_attribute_absence ["maria_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_mariadb_firewall_rule"; c := 1]) == 0
}

azure_attribute_absence ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_firewall_rule"
    not resource.properties.start_ip_address
}

azure_attribute_absence ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_firewall_rule"
    not resource.properties.end_ip_address
}

azure_issue["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mariadb_firewall_rule";
              contains(r.properties.server_name, resource.properties.compiletime_identity);
              not contains(r.properties.start_ip_address, "0.0.0.0");
              not contains(r.properties.end_ip_address, "0.0.0.0");
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mariadb_firewall_rule";
              contains(r.properties.server_name, concat(".", [resource.type, resource.name]));
              not contains(r.properties.start_ip_address, "0.0.0.0");
              not contains(r.properties.end_ip_address, "0.0.0.0");
              c := 1]) == 0
}

# azure_issue ["maria_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mariadb_firewall_rule"
#     contains(resource.properties.start_ip_address, "0.0.0.0")
# }

# azure_issue ["maria_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mariadb_firewall_rule"
#     contains(resource.properties.end_ip_address, "0.0.0.0")
# }

maria_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
    not azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
}


maria_ingress_from_any_ip_disabled_err = "Resource azurerm_mariadb_server and azurerm_mariadb_firewall_rule need to be exist and property 'start_ip_address' and 'end_ip_address' need to be exist under azurerm_mariadb_firewall_rule as well. one or all are missing from the resource." {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
} else = "MariaDB currently allowing ingress from all Azure-internal IP addresses" {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-012",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MariaDB firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "azurerm_mariadb_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_firewall_rule"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server
# PR-AZR-TRF-SQL-056

default mairadb_ssl_enforcement_enabled = null
azure_attribute_absence ["mairadb_ssl_enforcement_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    not resource.properties.ssl_enforcement_enabled
}

azure_issue ["mairadb_ssl_enforcement_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    resource.properties.ssl_enforcement_enabled == false
}

mairadb_ssl_enforcement_enabled {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not azure_attribute_absence["mairadb_ssl_enforcement_enabled"]
    not azure_issue["mairadb_ssl_enforcement_enabled"]
}

mairadb_ssl_enforcement_enabled = false {
    azure_issue["mairadb_ssl_enforcement_enabled"]
}

mairadb_ssl_enforcement_enabled = false {
    azure_attribute_absence["mairadb_ssl_enforcement_enabled"]
}


mairadb_ssl_enforcement_enabled_err = "azurerm_mariadb_server property 'ssl_enforcement_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["mairadb_ssl_enforcement_enabled"]
} else = "ssl enforcement is currently not enabled on MariaDB server." {
    azure_issue["mairadb_ssl_enforcement_enabled"]
}

mairadb_ssl_enforcement_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-056",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure ssl enforcement is enabled on MariaDB Server.",
    "Policy Description": "Enable SSL connection on MariaDB Servers. Rationale: SSL connectivity helps to provide a new layer of security, by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application.",
    "Resource Type": "azurerm_mariadb_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server
# PR-AZR-TRF-SQL-057

default mairadb_public_access_disabled = null

# is_private_endpoint_exist["mairadb_public_access_disabled"] {
#     count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) > 0
# }

#public_network_access_enabled Defaults to true if not exist.
azure_attribute_absence["mairadb_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    not has_property(resource.properties, "public_network_access_enabled")
}

azure_issue["mairadb_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    resource.properties.public_network_access_enabled == true
}

# mairadb_public_access_disabled {
#     lower(input.resources[_].type) == "azurerm_mariadb_server"
#     is_private_endpoint_exist["mairadb_public_access_disabled"]
# } 

mairadb_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not azure_attribute_absence["mairadb_public_access_disabled"]
    not azure_issue["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_attribute_absence["mairadb_public_access_disabled"]
    #not is_private_endpoint_exist["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_issue["mairadb_public_access_disabled"]
    #not is_private_endpoint_exist["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled_err = "Resource azurerm_mariadb_server's property 'public_network_access_enabled' need to be exist. its missing from the resource." {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_attribute_absence["mairadb_public_access_disabled"]
    #not is_private_endpoint_exist["mairadb_public_access_disabled"]
} else = "Public Network Access is currently not disabled on MariaDB Server." {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_issue["mairadb_public_access_disabled"]
    #not is_private_endpoint_exist["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-057",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure MariaDB servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for MariaDB Server",
    "Resource Type": "azurerm_mariadb_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server
# PR-AZR-TRF-SQL-058

default mariadb_geo_redundant_backup_enabled = null

azure_attribute_absence["mariadb_geo_redundant_backup_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    not resource.properties.geo_redundant_backup_enabled
}

azure_issue["mariadb_geo_redundant_backup_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    resource.properties.geo_redundant_backup_enabled == false
}

mariadb_geo_redundant_backup_enabled {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not azure_attribute_absence["mariadb_geo_redundant_backup_enabled"]
    not azure_issue["mariadb_geo_redundant_backup_enabled"]
}

mariadb_geo_redundant_backup_enabled = false {
    azure_attribute_absence["mariadb_geo_redundant_backup_enabled"]
}

mariadb_geo_redundant_backup_enabled = false {
    azure_issue["mariadb_geo_redundant_backup_enabled"]
}

mariadb_geo_redundant_backup_enabled_err = "azurerm_postgresql_server property 'geo_redundant_backup_enabled' need to be exist. Its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["mariadb_geo_redundant_backup_enabled"]
} else = "Geo-redundant backup is currently not enabled on MariaDB server." {
    azure_issue["mariadb_geo_redundant_backup_enabled"]
}

mariadb_geo_redundant_backup_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-058",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Geo-redundant backup is enabled on MariaDB server.",
    "Policy Description": "Azure Database for MariaDB provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.",
    "Resource Type": "azurerm_mariadb_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server"
}


# PR-AZR-TRF-SQL-059

default mariadb_server_uses_privatelink = null

azure_attribute_absence ["mariadb_server_uses_privatelink"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

azure_issue ["mariadb_server_uses_privatelink"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_id, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_id, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_alias, resource.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_private_endpoint";
              contains(r.properties.private_service_connection[_].private_connection_resource_alias, concat(".", [resource.type, resource.name]));
              c := 1]) == 0
}

mariadb_server_uses_privatelink = false {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_attribute_absence["mariadb_server_uses_privatelink"]
}

mariadb_server_uses_privatelink {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not azure_attribute_absence["mariadb_server_uses_privatelink"]
    not azure_issue["mariadb_server_uses_privatelink"]
}

mariadb_server_uses_privatelink = false {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_issue["mariadb_server_uses_privatelink"]
}

mariadb_server_uses_privatelink_err = "azurerm_mariadb_server should have link with azurerm_private_endpoint and azurerm_private_endpoint's private_service_connection either need to have 'private_connection_resource_id' or 'private_connection_resource_alias' property. Seems there is no link established or mentioed properties are missing." {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_attribute_absence["mariadb_server_uses_privatelink"]
} else = "MariaDB server currently not using private link" {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_issue["mariadb_server_uses_privatelink"]
}

mariadb_server_uses_privatelink_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-059",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MariaDB server should use private link",
    "Policy Description": "Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your MariaDB Server instances, data leakage risks are reduced.",
    "Resource Type": "azurerm_mariadb_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server"
}
