package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_firewall_rule

# PR-AZR-0145-TRF

default maria_ingress_from_any_ip_disabled = null

azure_attribute_absence ["maria_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_mariadb_server"; c := 1]) != count([c | input.resources[_].type == "azurerm_mariadb_firewall_rule"; c := 1])
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

azure_issue ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_firewall_rule"
    contains(resource.properties.start_ip_address, "0.0.0.0")
}

azure_issue ["maria_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_firewall_rule"
    contains(resource.properties.end_ip_address, "0.0.0.0")
}

maria_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
    not azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled = false {
    azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
}


maria_ingress_from_any_ip_disabled_err = "Resource azurerm_mariadb_server and azurerm_mariadb_firewall_rule need to be exist and property 'start_ip_address' and 'end_ip_address' need to be exist under azurerm_mariadb_firewall_rule as well. one or all are missing from the resource." {
    azure_attribute_absence["maria_ingress_from_any_ip_disabled"]
} else = "MariaDB currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["maria_ingress_from_any_ip_disabled"]
}

maria_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-0145-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MariaDB should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MariaDB firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "azurerm_mariadb_firewall_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_firewall_rule"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server
# PR-AZR-0189-TRF

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
    "Policy Code": "PR-AZR-0189-TRF",
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
# PR-AZR-0190-TRF

default mairadb_public_access_disabled = null

# public_network_access_enabled Defaults to true if not exist. This was an issue because we need to fail if property not exist and also need to passed if property has value false.
# if property does not exist it has false value in OPA, and explicitly setting false value will be treated as property not exist as well. so we need to implement a comparison like below.
no_azure_issue(resource_type) {
    count([c | input.resources[_].type == resource_type; c := 1]) == count([c | r := input.resources[_];
               r.type == resource_type;
               r.properties.public_network_access_enabled == false; # this is not same as not r.properties.public_network_access_enabled. not will give you correct result if property does not exist
               c := 1])
} else = false {
	true
}

mairadb_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    no_azure_issue("azurerm_mariadb_server")
} else = false {
	lower(input.resources[_].type) == "azurerm_mariadb_server"
}

mairadb_public_access_disabled_err = "Public Network Access is currently not disabled on MariaDB Server." {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not no_azure_issue("azurerm_mariadb_server")
}

mairadb_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0190-TRF",
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
# PR-AZR-0191-TRF

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
    "Policy Code": "PR-AZR-0191-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Geo-redundant backup is enabled on MariaDB server.",
    "Policy Description": "Azure Database for MariaDB provides the flexibility to choose between locally redundant or geo-redundant backup storage in the General Purpose and Memory Optimized tiers. When the backups are stored in geo-redundant backup storage, they are not only stored within the region in which your server is hosted, but are also replicated to a paired data center. This provides better protection and ability to restore your server in a different region in the event of a disaster. The Basic tier only offers locally redundant backup storage.",
    "Resource Type": "azurerm_mariadb_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server"
}
