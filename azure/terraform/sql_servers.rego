package rule

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server

#
# Always use Private Endpoint for Azure MSSQL Database and SQL Managed Instance (SQL MI resource is not available for terraform yet. 
# visit: https://github.com/hashicorp/terraform-provider-azurerm/issues/1747)
#

# PR-AZR-0128-TRF

default sql_public_access_disabled = null
#  Defaults to true
azure_attribute_absence["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not resource.properties.public_network_access_enabled
}

azure_issue["sql_public_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    resource.properties.public_network_access_enabled == true
}

sql_public_access_disabled {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    not azure_attribute_absence["sql_public_access_disabled"]
    not azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_mssql_server"
    azure_attribute_absence["sql_public_access_disabled"]
    azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled = false {
    azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled_err = "Public Network Access is currently not disabled on MSSQL Server." {
    azure_issue["sql_public_access_disabled"]
}

sql_public_access_disabled_metadata := {
    "Policy Code": "PR-AZR-0128-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure SQL servers don't have public network access enabled",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}

# https://docs.microsoft.com/en-us/azure/templates/azurerm_sql_server
# Always use Private Endpoint for Azure SQL Database and SQL Managed Instance
# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server
# This resource provides usage of Microsoft SQL Azure Database server using an older sku based model. 
# It is recommended going forward to use azurerm_mssql_server resource which provides support for vcores.
# (code is kept for reference but not used anywhere)
default sql_public_access = null

azure_issue["sql_public_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_sql_server"
    lower(resource.properties.publicNetworkAccess) != "disabled"
}

sql_public_access {
    lower(input.resources[_].type) == "azurerm_sql_server"
    not azure_issue["sql_public_access"]
}

sql_public_access = false {
    azure_issue["sql_public_access"]
}

sql_public_access_err = "SQL servers with public access detected!" {
    azure_issue["sql_public_access"]
}

sql_public_access_metadata := {
    "Policy Code": "",
    "Type": "IaC",
    "Product": "",
    "Language": "Terraform",
    "Policy Title": "SQL servers with public access detected!",
    "Policy Description": "Always use Private Endpoint for Azure SQL Database and SQL Managed Instance",
    "Resource Type": "azurerm_sql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_server"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server

# PR-AZR-0133-TRF

default sql_server_login = null


azure_attribute_absence["sql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    not resource.properties.administrator_login
}

no_azure_issue["sql_server_login"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_server"
    lower(resource.properties.administrator_login) != "admin"
    lower(resource.properties.administrator_login) != "administrator"
}

sql_server_login {
    not azure_attribute_absence["sql_server_login"]
    no_azure_issue["sql_server_login"]
}

sql_server_login = false {
    azure_attribute_absence["sql_server_login"]
}

sql_server_login = false {
    not no_azure_issue["sql_server_login"]
}

sql_server_login_err = "azurerm_mssql_server property 'administrator_login' need to be exist. Its missing from the resource." {
    azure_attribute_absence["sql_server_login"]
} else = "Azure SQL Server login is currently set to admin or administrator on the resource. Please change the name" {
    not no_azure_issue["sql_server_login"]
}

sql_server_login_metadata := {
    "Policy Code": "PR-AZR-0133-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure SQL Server administrator login does not contains 'Admin/Administrator' as name",
    "Policy Description": "You must designate a Server admin login when you create an Azure SQL server. SQL server creates this account as a login in the master database. Only one such account can exist. This account connects using SQL Server authentication (username and password). It is recommended to avoid using names like 'admin' or 'administrator', which are targeted in brute force dictionary attacks.",
    "Resource Type": "azurerm_mssql_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server"
}

# PR-AZR-0147-TRF

default mssql_ingress_from_any_ip_disabled = null
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

azure_issue ["mssql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_firewall_rule"
    contains(resource.properties.start_ip_address, "0.0.0.0")
}

azure_issue ["mssql_ingress_from_any_ip_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_mssql_firewall_rule"
    contains(resource.properties.end_ip_address, "0.0.0.0")
}

mssql_ingress_from_any_ip_disabled {
    lower(input.resources[_].type) == "azurerm_mssql_firewall_rule"
    not azure_attribute_absence["mssql_ingress_from_any_ip_disabled"]
    not azure_issue["mssql_ingress_from_any_ip_disabled"]
}

mssql_ingress_from_any_ip_disabled = false {
    azure_issue["mssql_ingress_from_any_ip_disabled"]
}

mssql_ingress_from_any_ip_disabled = false {
    azure_attribute_absence["mssql_ingress_from_any_ip_disabled"]
}


mssql_ingress_from_any_ip_disabled_err = "azurerm_mssql_firewall_rule property 'start_ip_address' and 'end_ip_address' need to be exist. one or both are missing from the resource." {
    azure_attribute_absence["mssql_ingress_from_any_ip_disabled"]
} else = "MSSQL Database Server currently allowing ingress from all Azure-internal IP addresses" {
    azure_issue["mssql_ingress_from_any_ip_disabled"]
}

mssql_ingress_from_any_ip_disabled_metadata := {
    "Policy Code": "PR-AZR-0147-TRF",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "MSSQL Database Server should not allow ingress from all Azure-internal IP addresses (0.0.0.0/0)",
    "Policy Description": "This policy will identify PostgreSQL Database Server firewall rule that are currently allowing ingress from all Azure-internal IP addresses",
    "Resource Type": "azurerm_mssql_firewall_rule",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_firewall_rule"
}


