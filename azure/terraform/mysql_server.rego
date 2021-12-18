package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_firewall_rule

# PR-AZR-TRF-SQL-014

default mysql_ingress_from_any_ip_disabled = null

azure_attribute_absence ["mysql_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_mysql_firewall_rule"; c := 1]) == 0
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

azure_issue["mysql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mysql_firewall_rule";
              contains(r.properties.server_name, resource.properties.compiletime_identity);
              not contains(r.properties.start_ip_address, "0.0.0.0");
              not contains(r.properties.end_ip_address, "0.0.0.0");
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mysql_firewall_rule";
              contains(r.properties.server_name, concat(".", [resource.type, resource.name]));
              not contains(r.properties.start_ip_address, "0.0.0.0");
              not contains(r.properties.end_ip_address, "0.0.0.0");
              c := 1]) == 0
}

# azure_issue ["mysql_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mysql_firewall_rule"
#     contains(resource.properties.start_ip_address, "0.0.0.0")
# }

# azure_issue ["mysql_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mysql_firewall_rule"
#     contains(resource.properties.end_ip_address, "0.0.0.0")
# }

mysql_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    not azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
    not azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
}


mysql_ingress_from_any_ip_disabled_err = "Resource azurerm_mysql_server and azurerm_mysql_firewall_rule need to be exist and property 'start_ip_address' and 'end_ip_address' need to be exist under azurerm_mysql_firewall_rule as well. one or all are missing from the resource." {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_attribute_absence["mysql_ingress_from_any_ip_disabled"]
} else = "MySQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_issue["mysql_ingress_from_any_ip_disabled"]
}

mysql_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-014",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MySQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MySQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "azurerm_mysql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_firewall_rule"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server

# PR-AZR-TRF-SQL-016

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
    "Policy Code": "PR-AZR-TRF-SQL-016",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure MySQL Database Server accepts only SSL connections",
    "Policy Description": "This policy will identify MySQL Database Server which are not enforcing all the incoming connection over SSL and alert if found.",
    "Resource Type": "azurerm_mysql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server

# PR-AZR-TRF-SQL-060

default mysql_public_access_disabled = null

# public_network_access_enabled Defaults to true if not exist. This was an issue because we need to fail if property not exist and also need to passed if property has value false.
# if property does not exist it has false value in OPA, and explicitly setting false value will be treated as property not exist as well. so we need to implement a comparison like below.
# no_azure_issue(resource_type) {
#     count([c | input.resources[_].type == resource_type; c := 1]) == count([c | r := input.resources[_];
#                r.type == resource_type;
#                r.properties.public_network_access_enabled == false; # this is not same as not r.properties.public_network_access_enabled. not will give you correct result if property does not exist
#                c := 1])
# } else = false {
# 	true
# }

# is_private_endpoint_exist["mysql_public_access_disabled"] {
#     count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) > 0
# }

azure_attribute_absence["mysql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    not has_property(resource.properties, "public_network_access_enabled")
}

azure_issue["mysql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    resource.properties.public_network_access_enabled == true
}

# mysql_public_access_disabled {
#     lower(input.resources[_].type) == "azurerm_mysql_server"
#     is_private_endpoint_exist["mysql_public_access_disabled"]
# } 

mysql_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    not azure_attribute_absence["mysql_public_access_disabled"]
    not azure_issue["mysql_public_access_disabled"]
}

mysql_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_attribute_absence["mysql_public_access_disabled"]
    #not is_private_endpoint_exist["mysql_public_access_disabled"]
}

mysql_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_issue["mysql_public_access_disabled"]
    #not is_private_endpoint_exist["mysql_public_access_disabled"]
}

mysql_public_access_disabled_err = "Resource azurerm_mysql_server's property 'public_network_access_enabled' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_attribute_absence["mysql_public_access_disabled"]
    #not is_private_endpoint_exist["mysql_public_access_disabled"]
} else = "Public Network Access is currently not disabled on MySQL Server." {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_issue["mysql_public_access_disabled"]
    #not is_private_endpoint_exist["mysql_public_access_disabled"]
}

mysql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-060",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure MySQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure MySQL Database Server",
    "Resource Type": "azurerm_mysql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server
# PR-AZR-TRF-SQL-061
#

default mysql_server_latest_tls_configured = null

#default to TLSEnforcementDisabled
azure_attribute_absence["mysql_server_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    not resource.properties.ssl_minimal_tls_version_enforced
}

azure_issue["mysql_server_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
    lower(resource.properties.ssl_minimal_tls_version_enforced) != "tls1_2"
}

mysql_server_latest_tls_configured {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    not azure_attribute_absence["mysql_server_latest_tls_configured"]
    not azure_issue["mysql_server_latest_tls_configured"]
}

mysql_server_latest_tls_configured = false {
    azure_attribute_absence["mysql_server_latest_tls_configured"]
}

mysql_server_latest_tls_configured = false {
    azure_issue["mysql_server_latest_tls_configured"]
}

mysql_server_latest_tls_configured_err = "azurerm_mysql_server property 'ssl_minimal_tls_version_enforced' need to be exist. Its missing from the resource. Please set the value to 'TLS1_2' after property addition." {
    azure_attribute_absence["mysql_server_latest_tls_configured"]
} else = "Azure MySQL Server currently dont have latest version of tls configured" {
    azure_issue["mysql_server_latest_tls_configured"]
}

storage_account_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-061",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure MySQL Server has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure MySQL Server which dont have latest version of tls configured and give alert",
    "Resource Type": "azurerm_mysql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server"
}

# PR-AZR-TRF-SQL-002

default mysql_server_uses_privatelink = null

azure_attribute_absence ["mysql_server_uses_privatelink"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

azure_issue ["mysql_server_uses_privatelink"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mysql_server"
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

mysql_server_uses_privatelink = false {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_attribute_absence["mysql_server_uses_privatelink"]
}

mysql_server_uses_privatelink {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    not azure_attribute_absence["mysql_server_uses_privatelink"]
    not azure_issue["mysql_server_uses_privatelink"]
}

mysql_server_uses_privatelink = false {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_issue["mysql_server_uses_privatelink"]
}

mysql_server_uses_privatelink_err = "azurerm_mysql_server should have link with azurerm_private_endpoint and azurerm_private_endpoint's private_service_connection either need to have 'private_connection_resource_id' or 'private_connection_resource_alias' property. Seems there is no link established or mentioed properties are missing." {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_attribute_absence["mysql_server_uses_privatelink"]
} else = "MySQL server currently not using private link" {
    lower(input.resources[_].type) == "azurerm_mysql_server"
    azure_issue["mysql_server_uses_privatelink"]
}

mysql_server_uses_privatelink_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MySQL server should use private link",
    "Policy Description": "Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your MySQL Server instances, data leakage risks are reduced.",
    "Resource Type": "azurerm_mysql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server"
}