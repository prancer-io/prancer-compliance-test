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