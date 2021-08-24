package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_firewall_rule

# PR-AZR-0148-TRF

default mysql_ingress_from_any_ip_disabled = null
azure_attribute_absence ["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_firewall_rule"
    not resource.properties.start_ip_address
}

azure_attribute_absence ["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_firewall_rule"
    not resource.properties.end_ip_address
}

azure_issue ["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_firewall_rule"
    contains(resource.properties.start_ip_address, "0.0.0.0")
}

azure_issue ["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_firewall_rule"
    contains(resource.properties.end_ip_address, "0.0.0.0")
}

mysql_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_mysql_firewall_rule"
    not azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
    not azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled = false {
    azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
}


mysql_ingress_from_any_ip_disabled_err = "azurerm_mysql_firewall_rule property 'start_ip_address' and 'end_ip_address' need to be exist. one or both are missing from the resource." {
    azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
} else = "MSSQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-0148-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MySQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MySQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "azurerm_mysql_firewall_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_firewall_rule"
}