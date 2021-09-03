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
    lower(input.resources[_].type) == "azurerm_mariadb_firewall_rule"
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
} else = "ssl enforcement is currently not enabled on MariaDB erver." {
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
#  Defaults to true
azure_attribute_absence["mairadb_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    not resource.properties.public_network_access_enabled
}

azure_issue["mairadb_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mariadb_server"
    resource.properties.public_network_access_enabled == true
}

mairadb_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    not azure_attribute_absence["mairadb_public_access_disabled"]
    not azure_issue["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_mariadb_server"
    azure_attribute_absence["mairadb_public_access_disabled"]
    azure_issue["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled = false {
    azure_issue["mairadb_public_access_disabled"]
}

mairadb_public_access_disabled_err = "Public Network Access is currently not disabled on MariaDB Server." {
    azure_issue["sql_public_access_disabled"]
}

mairadb_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0190-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure MariaDB servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for MariaDB Server",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server"
}
