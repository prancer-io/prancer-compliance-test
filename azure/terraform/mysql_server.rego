package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_firewall_rule

# PR-AZR-0148-TRF

default mysql_ingress_from_any_ip_disabled = null

azure_attribute_absence ["mysql_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_mysql_server"; c := 1]) != count([c | input.resources[_].type == "azurerm_mysql_firewall_rule"; c := 1])
}

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


mysql_ingress_from_any_ip_disabled_err = "Resource azurerm_mysql_server and azurerm_mysql_firewall_rule need to be exist and property 'start_ip_address' and 'end_ip_address' need to be exist under azurerm_mysql_firewall_rule as well. one or all are missing from the resource." {
    azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
} else = "MySQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
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


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server

# PR-AZR-0184-TRF

default mysql_server_ssl_enforcement_enabled = null
azure_attribute_absence ["mysql_server_ssl_enforcement_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    not resource.properties.ssl_enforcement_enabled
}

azure_issue ["mysql_server_ssl_enforcement_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    resource.properties.ssl_enforcement_enabled != true
}

mysql_server_ssl_enforcement_enabled {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    not azure_attribute_absence["mysql_server_ssl_enforcement_enabled"]
    not azure_issue["mysql_server_ssl_enforcement_enabled"]
}

mysql_server_ssl_enforcement_enabled = false {
    azure_issue["mysql_server_ssl_enforcement_enabled"]
}

mysql_server_ssl_enforcement_enabled = false {
    azure_attribute_absence["mysql_server_ssl_enforcement_enabled"]
}


mysql_server_ssl_enforcement_enabled_err = "azurerm_mysql_server property 'ssl_enforcement_enabled' need to be exist. Its missing from the resource." {
    azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
} else = "MySQL Database Server currently allowing insecure connections. Enforce it to accept only connection over SSL" {
    azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_server_ssl_enforcement_enabled_metadata := {
    "Policy Code": "PR-AZR-0184-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure MySQL Database Server accepts only SSL connections",
    "Policy Description": "This policy will identify MySQL Database Server which are not enforcing all the incoming connection over SSL and alert if found.",
    "Resource Type": "azurerm_mysql_firewall_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server

# PR-AZR-0030-TRF

default mysql_public_access_disabled = null
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

mysql_public_access_disabled {
    no_azure_issue("azurerm_mysql_server")
} else = false {
	true
}

mysql_public_access_disabled_err = "Public Network Access is currently not disabled on MySQL Server." {
    not no_azure_issue("azurerm_mysql_server")
}

mysql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0030-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure MySQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure MySQL Database Server",
    "Resource Type": "azurerm_mysql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server"
}