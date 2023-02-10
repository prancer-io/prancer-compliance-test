package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server

#
# Always use Private Endpoint for Azure MSSQL Database and SQL Managed Instance (SQL MI resource is not available for terraform yet. 
# visit: https://github.com/hashicorp/terraform-provider-azurerm/issues/1747)
#

# PR-AZR-TRF-SQL-033

default sql_public_access_disabled = null

sql_dont_have_private_endpoint ["sql_public_access_disabled"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

sql_dont_have_private_endpoint ["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
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

azure_attribute_absence["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    not has_property(resource.properties, "public_network_access_enabled")
}

azure_issue["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    resource.properties.public_network_access_enabled == true
}

sql_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not sql_dont_have_private_endpoint["sql_public_access_disabled"]
} 

sql_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["sql_public_access_disabled"]
    not azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["sql_public_access_disabled"]
    sql_dont_have_private_endpoint["sql_public_access_disabled"]
}

sql_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["sql_public_access_disabled"]
    sql_dont_have_private_endpoint["sql_public_access_disabled"]
}

sql_public_access_disabled_err = "Resource azurerm_sql_server and azurerm_private_endpoint or property 'public_network_access_enabled' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["sql_public_access_disabled"]
    sql_dont_have_private_endpoint["sql_public_access_disabled"]
} else = "Public Network Access is currently not disabled on SQL Server." {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["sql_public_access_disabled"]
    sql_dont_have_private_endpoint["sql_public_access_disabled"]
}

sql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-033",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure SQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database Server and SQL Managed Instance",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}


# PR-AZR-TRF-SQL-047

default mssql_public_access_disabled = null

mssql_dont_have_private_endpoint ["mssql_public_access_disabled"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

mssql_dont_have_private_endpoint ["mssql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
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

azure_attribute_absence["mssql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not has_property(resource.properties, "public_network_access_enabled")
}

azure_issue["mssql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    resource.properties.public_network_access_enabled == true
}

mssql_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not mssql_dont_have_private_endpoint["mssql_public_access_disabled"]
} 

mssql_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_public_access_disabled"]
    not azure_issue["mssql_public_access_disabled"]
}

mssql_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_public_access_disabled"]
    mssql_dont_have_private_endpoint["mssql_public_access_disabled"]
}

mssql_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_public_access_disabled"]
    mssql_dont_have_private_endpoint["mssql_public_access_disabled"]
}

mssql_public_access_disabled_err = "Resource azurerm_mssql_server and azurerm_private_endpoint or property 'public_network_access_enabled' need to be exist. Its missing from the resource." {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_public_access_disabled"]
    mssql_dont_have_private_endpoint["mssql_public_access_disabled"]
} else = "Public Network Access is currently not disabled on SQL Server." {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_public_access_disabled"]
    mssql_dont_have_private_endpoint["mssql_public_access_disabled"]
}

mssql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-047",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure SQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database Server and SQL Managed Instance",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server

# PR-AZR-TRF-SQL-048

default mssql_server_login = null

azure_attribute_absence["mssql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not resource.properties.administrator_login
}

no_azure_issue["mssql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not contains(lower(resource.properties.administrator_login), "admin")
    not contains(lower(resource.properties.administrator_login), "administrator")
}

mssql_server_login {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_server_login"]
    no_azure_issue["mssql_server_login"]
}

mssql_server_login = false {
    azure_attribute_absence["mssql_server_login"]
}

mssql_server_login = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not no_azure_issue["mssql_server_login"]
}

mssql_server_login_err = "azurerm_mssql_server property 'administrator_login' need to be exist. Its missing from the resource." {
    azure_attribute_absence["mssql_server_login"]
} else = "Azure SQL Server login is currently set to admin or administrator on the resource. Please change the name" {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not no_azure_issue["mssql_server_login"]
}

mssql_server_login_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-048",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}


# PR-AZR-TRF-SQL-034

default sql_server_login = null

azure_attribute_absence["sql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    not resource.properties.administrator_login
}

no_azure_issue["sql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    not contains(lower(resource.properties.administrator_login), "admin")
    not contains(lower(resource.properties.administrator_login), "administrator")
}

sql_server_login {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["sql_server_login"]
    no_azure_issue["sql_server_login"]
}

sql_server_login = false {
    azure_attribute_absence["sql_server_login"]
}

sql_server_login = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not no_azure_issue["sql_server_login"]
}

sql_server_login_err = "azurerm_sql_server property 'administrator_login' need to be exist. Its missing from the resource." {
    azure_attribute_absence["sql_server_login"]
} else = "Azure SQL Server login is currently set to admin or administrator on the resource. Please change the name" {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not no_azure_issue["sql_server_login"]
}

sql_server_login_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-034",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server"
}


# PR-AZR-TRF-SQL-035
# As per Farshid Mahdavipour
# this shoud be a smart policy 
# we have to check for firewall 
# but if it is on private endpoint
# it means there is no public connectivity
# so the rule should pass

default sql_ingress_from_any_ip_disabled = null

mssql_dont_have_private_endpoint["sql_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

mssql_dont_have_private_endpoint["sql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
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

azure_attribute_absence ["sql_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_mssql_firewall_rule"; c := 1]) == 0
}

azure_attribute_absence ["sql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_firewall_rule"
    not resource.properties.start_ip_address
}

azure_attribute_absence ["sql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_firewall_rule"
    not resource.properties.end_ip_address
}

azure_issue["sql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_firewall_rule";
              contains(r.properties.server_name, resource.properties.compiletime_identity);
              not contains(r.properties.start_ip_address, "0.0.0.0");
              not contains(r.properties.end_ip_address, "0.0.0.0");
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_firewall_rule";
              contains(r.properties.server_name, concat(".", [resource.type, resource.name]));
              not contains(r.properties.start_ip_address, "0.0.0.0");
              not contains(r.properties.end_ip_address, "0.0.0.0");
              c := 1]) == 0
}

# azure_issue ["sql_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mssql_firewall_rule"
#     contains(resource.properties.start_ip_address, "0.0.0.0")
# }

# azure_issue ["sql_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mssql_firewall_rule"
#     contains(resource.properties.end_ip_address, "0.0.0.0")
# }

sql_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not mssql_dont_have_private_endpoint["sql_ingress_from_any_ip_disabled"]
}

sql_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["sql_ingress_from_any_ip_disabled"]
    not azure_issue["sql_ingress_from_any_ip_disabled"]
}

sql_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["sql_ingress_from_any_ip_disabled"]
    mssql_dont_have_private_endpoint["sql_ingress_from_any_ip_disabled"]
}

sql_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["sql_ingress_from_any_ip_disabled"]
    mssql_dont_have_private_endpoint["sql_ingress_from_any_ip_disabled"]
}

sql_ingress_from_any_ip_disabled_err = "Resource azurerm_sql_server and azurerm_private_endpoint or azurerm_mssql_firewall_rule need to be exist and property 'start_ip_address' and 'end_ip_address' need to be exist under azurerm_mssql_firewall_rule as well. one or all are missing from the resource." {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["sql_ingress_from_any_ip_disabled"]
    mssql_dont_have_private_endpoint["sql_ingress_from_any_ip_disabled"]
} else = "MSSQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["sql_ingress_from_any_ip_disabled"]
    mssql_dont_have_private_endpoint["sql_ingress_from_any_ip_disabled"]
}

sql_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-035",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MSSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MSSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_firewall_rule"
}


# PR-AZR-TRF-SQL-068
# As per Farshid Mahdavipour
# this shoud be a smart policy 
# we have to check for firewall 
# but if it is on private endpoint
# it means there is no public connectivity
# so the rule should pass

default mssql_ingress_from_any_ip_disabled = null

mssql_dont_have_private_endpoint["mssql_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

mssql_dont_have_private_endpoint["mssql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
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

azure_attribute_absence ["mssql_ingress_from_any_ip_disabled"] {
    count([c | input.resources[_].type == "azurerm_mssql_firewall_rule"; c := 1]) == 0
}

azure_attribute_absence ["mssql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_firewall_rule"
    not resource.properties.start_ip_address
}

azure_attribute_absence ["mssql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_firewall_rule"
    not resource.properties.end_ip_address
}

azure_issue["mssql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_firewall_rule";
              contains(r.properties.server_name, resource.properties.compiletime_identity);
              not contains(r.properties.start_ip_address, "0.0.0.0");
              not contains(r.properties.end_ip_address, "0.0.0.0");
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_firewall_rule";
              contains(r.properties.server_name, concat(".", [resource.type, resource.name]));
              not contains(r.properties.start_ip_address, "0.0.0.0");
              not contains(r.properties.end_ip_address, "0.0.0.0");
              c := 1]) == 0
}

# azure_issue ["mssql_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mssql_firewall_rule"
#     contains(resource.properties.start_ip_address, "0.0.0.0")
# }

# azure_issue ["mssql_ingress_from_any_ip_disabled"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_mssql_firewall_rule"
#     contains(resource.properties.end_ip_address, "0.0.0.0")
# }

mssql_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not mssql_dont_have_private_endpoint["mssql_ingress_from_any_ip_disabled"]
}

mssql_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_ingress_from_any_ip_disabled"]
    not azure_issue["mssql_ingress_from_any_ip_disabled"]
}

mssql_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_ingress_from_any_ip_disabled"]
    mssql_dont_have_private_endpoint["mssql_ingress_from_any_ip_disabled"]
}

mssql_ingress_from_any_ip_disabled = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_ingress_from_any_ip_disabled"]
    mssql_dont_have_private_endpoint["mssql_ingress_from_any_ip_disabled"]
}

mssql_ingress_from_any_ip_disabled_err = "Resource azurerm_mssql_server and azurerm_private_endpoint or azurerm_mssql_firewall_rule need to be exist and property 'start_ip_address' and 'end_ip_address' need to be exist under azurerm_mssql_firewall_rule as well. one or all are missing from the resource." {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_ingress_from_any_ip_disabled"]
    mssql_dont_have_private_endpoint["mssql_ingress_from_any_ip_disabled"]
} else = "MSSQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_ingress_from_any_ip_disabled"]
    mssql_dont_have_private_endpoint["mssql_ingress_from_any_ip_disabled"]
}

mssql_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-068",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MSSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify MSSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_firewall_rule"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server
# PR-AZR-TRF-SQL-069
# Once minimum_tls_version is set it is not possible to remove this setting and must be given a valid value for any further updates to the resource.

default mssql_server_latest_tls_configured = null

# no default
azure_attribute_absence["mssql_server_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not resource.properties.minimum_tls_version
}

azure_issue["mssql_server_latest_tls_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    to_number(resource.properties.minimum_tls_version) != 1.2
}

mssql_server_latest_tls_configured {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_server_latest_tls_configured"]
    not azure_issue["mssql_server_latest_tls_configured"]
}

mssql_server_latest_tls_configured = false {
    azure_attribute_absence["mssql_server_latest_tls_configured"]
}

mssql_server_latest_tls_configured = false {
    azure_issue["mssql_server_latest_tls_configured"]
}

mssql_server_latest_tls_configured_err = "azurerm_mssql_server property 'minimum_tls_version' need to be exist. Its missing from the resource. Please set the value to '1.2' after property addition." {
    azure_attribute_absence["mssql_server_latest_tls_configured"]
} else = "Azure MSSQL Server currently dont have latest version of tls configured" {
    azure_issue["mssql_server_latest_tls_configured"]
}

mssql_server_latest_tls_configured_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-069",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Azure MSSQL Server has latest version of tls configured",
    "Policy Description": "This policy will identify the Azure MSSQL Server which dont have latest version of tls configured and give alert",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}


# PR-AZR-TRF-SQL-071

default mssql_server_configured_with_vnet = null

azure_attribute_absence["mssql_server_configured_with_vnet"] {
    count([c | input.resources[_].type == "azurerm_mssql_virtual_network_rule"; c := 1]) == 0
}

azure_attribute_absence["mssql_server_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_virtual_network_rule"
    not resource.properties.server_id
}

azure_issue["mssql_server_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_virtual_network_rule";
              contains(r.properties.server_id, resource.properties.compiletime_identity);
              #lower(r.properties.state) == "enabled";
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_mssql_virtual_network_rule";
              contains(r.properties.server_id, concat(".", [resource.type, resource.name]));
              #lower(r.properties.state) == "enabled";
              c := 1]) == 0
}

mssql_server_configured_with_vnet {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_server_configured_with_vnet"]
    not azure_issue["mssql_server_configured_with_vnet"]
}

mssql_server_configured_with_vnet = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_server_configured_with_vnet"]
}

mssql_server_configured_with_vnet = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_server_configured_with_vnet"]
}

mssql_server_configured_with_vnet_err = "Make sure resource azurerm_mssql_server and azurerm_mssql_virtual_network_rule both exist and linked. either related resource or link is missing." {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_server_configured_with_vnet"]
} else = "VNET is currently not configured on SQL Server" {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_server_configured_with_vnet"]
}

mssql_server_configured_with_vnet_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-071",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that SQL Server configured with a virtual network",
    "Policy Description": "This policy audits any SQL Server not configured to use a virtual network service endpoint.",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_virtual_network_rule"
}


# PR-AZR-TRF-SQL-072

default sql_server_configured_with_vnet = null

azure_attribute_absence["sql_server_configured_with_vnet"] {
    count([c | input.resources[_].type == "azurerm_sql_virtual_network_rule"; c := 1]) == 0
}

azure_attribute_absence["sql_server_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_virtual_network_rule"
    not resource.properties.server_id
}

azure_issue["sql_server_configured_with_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    count([c | r := input.resources[_];
              r.type == "azurerm_sql_virtual_network_rule";
              contains(r.properties.server_name, resource.properties.compiletime_identity);
              #lower(r.properties.state) == "enabled";
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_sql_virtual_network_rule";
              contains(r.properties.server_name, concat(".", [resource.type, resource.name]));
              #lower(r.properties.state) == "enabled";
              c := 1]) == 0
}

sql_server_configured_with_vnet {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_attribute_absence["sql_server_configured_with_vnet"]
    not azure_issue["sql_server_configured_with_vnet"]
}

sql_server_configured_with_vnet = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["sql_server_configured_with_vnet"]
}

sql_server_configured_with_vnet = false {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["sql_server_configured_with_vnet"]
}

sql_server_configured_with_vnet_err = "Make sure resource azurerm_sql_server and azurerm_sql_virtual_network_rule both exist and linked. either related resource or link is missing." {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_attribute_absence["sql_server_configured_with_vnet"]
} else = "VNET is currently not configured on SQL Server" {
    lower(input.resources[_].type) == "azurerm_sql_server"
    azure_issue["sql_server_configured_with_vnet"]
}

sql_server_configured_with_vnet_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-072",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that SQL Server configured with a virtual network",
    "Policy Description": "This policy audits any SQL Server not configured to use a virtual network service endpoint.",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_virtual_network_rule"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint
# PR-AZR-TRF-SQL-076

default mssql_server_configured_with_private_endpoint = null

azure_attribute_absence ["mssql_server_configured_with_private_endpoint"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

azure_issue ["mssql_server_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
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

mssql_server_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_server_configured_with_private_endpoint"]
}

mssql_server_configured_with_private_endpoint {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["mssql_server_configured_with_private_endpoint"]
    not azure_issue["mssql_server_configured_with_private_endpoint"]
}

mssql_server_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_server_configured_with_private_endpoint"]
}

mssql_server_configured_with_private_endpoint_err = "azurerm_mssql_server should have link with azurerm_private_endpoint and azurerm_private_endpoint's private_service_connection either need to have 'private_connection_resource_id' or 'private_connection_resource_alias' property. Seems there is no link established or mentioed properties are missing." {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["mssql_server_configured_with_private_endpoint"]
} else = "Azure KeyVault currently not using private link" {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_issue["mssql_server_configured_with_private_endpoint"]
}

mssql_server_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-TRF-SQL-076",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure SQL Server should have private endpoints configured",
    "Policy Description": "Private endpoint connections enforce secure communication by enabling private connectivity to Azure SQL Server.",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}





