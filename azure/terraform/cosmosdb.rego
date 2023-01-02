package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account
#
# PR-AZR-TRF-ACD-001
#

default acd_ip_range_filter_configured = null

azure_attribute_absence["acd_ip_range_filter_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    not resource.properties.ip_range_filter
}

azure_issue["acd_ip_range_filter_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    count(resource.ip_range_filter) == 0
}

acd_ip_range_filter_configured {
    lower(input.resources[_].type) == "azurerm_cosmosdb_account"
    not azure_issue["acd_ip_range_filter_configured"]
    not azure_attribute_absence["acd_ip_range_filter_configured"]
}

acd_ip_range_filter_configured = false {
    azure_issue["acd_ip_range_filter_configured"]
}

acd_ip_range_filter_configured = false {
    azure_attribute_absence["acd_ip_range_filter_configured"]
}

acd_ip_range_filter_configured_err = "Azure Cosmos DB IP range filter currently not configured" {
    azure_issue["acd_ip_range_filter_configured"]
} else = "Azure Cosmos DB attribute ip_range_filter is missing from the resource" {
    azure_attribute_absence["acd_ip_range_filter_configured"]
}

acd_ip_range_filter_configured_metadata := {
    "Policy Code": "PR-AZR-TRF-ACD-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Cosmos DB IP range filter should be configured",
    "Policy Description": "This policy identifies Azure Cosmos DB with IP range filter not configured. Azure Cosmos DB should be restricted access from All Networks. It is recommended to add defined set of IP / IP range which can access Azure Cosmos DB from the Internet.",
    "Resource Type": "azurerm_cosmosdb_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account"
}


#
# PR-AZR-TRF-ACD-003
#

default acd_vnet_configured = null

azure_attribute_absence["acd_vnet_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    not has_property(resource.properties, "is_virtual_network_filter_enabled")
}

azure_issue["acd_vnet_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    resource.properties.is_virtual_network_filter_enabled != true
}

acd_vnet_configured {
    lower(input.resources[_].type) == "azurerm_cosmosdb_account"
    not azure_issue["acd_vnet_configured"]
    not azure_attribute_absence["acd_vnet_configured"]
}

acd_vnet_configured = false {
    azure_issue["acd_vnet_configured"]
}

acd_vnet_configured = false {
    azure_attribute_absence["acd_vnet_configured"]
}

acd_vnet_configured_err = "Azure Cosmos DB Virtual Network currently not configured" {
    azure_issue["acd_vnet_configured"]
} else = "Azure Cosmos DB attribute is_virtual_network_filter_enabled is missing from the resource" {
    azure_attribute_absence["acd_vnet_configured"]
}

acd_ip_range_filter_configured_metadata := {
    "Policy Code": "PR-AZR-TRF-ACD-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Cosmos DB Virtual network should be configured",
    "Policy Description": "This policy identifies Azure Cosmos DBs that are not configured with a Virtual network. Azure Cosmos DB by default is accessible from any source if the request is accompanied by a valid authorization token. By configuring Virtual network only requests originating from those subnets will get a valid response. It is recommended to configure Virtual network to Cosmos DB.",
    "Resource Type": "azurerm_cosmosdb_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account"
}


#
# PR-AZR-TRF-ACD-004
#

default acd_ip_range_filter_configured_to_block_public_inbound_access = null

azure_attribute_absence["acd_ip_range_filter_configured_to_block_public_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    not resource.properties.ip_range_filter
}

azure_issue["acd_ip_range_filter_configured_to_block_public_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    contains(resource.properties.ip_range_filter, "0.0.0.0")
}

acd_ip_range_filter_configured_to_block_public_inbound_access {
    lower(input.resources[_].type) == "azurerm_cosmosdb_account"
    not azure_issue["acd_ip_range_filter_configured_to_block_public_inbound_access"]
    not azure_attribute_absence["acd_ip_range_filter_configured_to_block_public_inbound_access"]
}

acd_ip_range_filter_configured_to_block_public_inbound_access = false {
    azure_issue["acd_ip_range_filter_configured_to_block_public_inbound_access"]
}

acd_ip_range_filter_configured_to_block_public_inbound_access = false {
    azure_attribute_absence["acd_ip_range_filter_configured_to_block_public_inbound_access"]
}

acd_ip_range_filter_configured_to_block_public_inbound_access_err = "Azure Cosmos DB IP range filter currently not configured" {
    azure_issue["acd_ip_range_filter_configured_to_block_public_inbound_access"]
} else = "Azure Cosmos DB attribute ip_range_filter missing from the resource. Make sure it does not contains 0.0.0.0" {
    azure_attribute_absence["acd_ip_range_filter_configured_to_block_public_inbound_access"]
}

acd_ip_range_filter_configured_to_block_public_inbound_access_metadata := {
    "Policy Code": "PR-AZR-TRF-ACD-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Cosmos DB shoud not allow traffic from public Azure datacenters",
    "Policy Description": "This policy identifies Cosmos DBs that allow traffic from public Azure datacenters. If you enable this option, the IP address 0.0.0.0 is added to the list of allowed IP addresses. The list of IPs allowed by this option is wide, so it limits the effectiveness of a firewall policy. So it is recommended not to select the 'Accept connections from within public Azure datacenters' option for your Cosmos DB.",
    "Resource Type": "azurerm_cosmosdb_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account"
}


#
# PR-AZR-ARM-ACD-005
#

# Defaults to true
default acd_disbaled_key_based_metadata_write_access = null

azure_attribute_absence["acd_disbaled_key_based_metadata_write_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    not has_property(resource.properties, "access_key_metadata_writes_enabled")
}

azure_issue["acd_disbaled_key_based_metadata_write_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_cosmosdb_account"
    resource.properties.access_key_metadata_writes_enabled == true
}

acd_disbaled_key_based_metadata_write_access {
    lower(input.resources[_].type) == "azurerm_cosmosdb_accounts"
    not azure_issue["acd_disbaled_key_based_metadata_write_access"]
    not azure_attribute_absence["acd_disbaled_key_based_metadata_write_access"]
}

acd_disbaled_key_based_metadata_write_access = false {
    azure_issue["acd_disbaled_key_based_metadata_write_access"]
}

acd_disbaled_key_based_metadata_write_access = false {
    azure_attribute_absence["acd_disbaled_key_based_metadata_write_access"]
}

acd_disbaled_key_based_metadata_write_access_err = "Azure Cosmos DB key based authentication currently not disbaled" {
    azure_issue["acd_disbaled_key_based_metadata_write_access"]
} else = "Azure Cosmos DB attribute access_key_metadata_writes_enabled is missing from the resource." {
    azure_attribute_absence["acd_disbaled_key_based_metadata_write_access"]
}

acd_disbaled_key_based_metadata_write_access_metadata := {
    "Policy Code": "PR-AZR-ARM-ACD-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Cosmos DB key based authentication should be disabled",
    "Policy Description": "This policy identifies Cosmos DBs that are enabled with key-based authentication. Disabling key-based metadata write access on Azure Cosmos DB prevents any changes to resources from a client connecting using the account keys. It is recommended to disable this feature for organizations who want higher degrees of control and governance for production environments.<br><br>NOTE: Enabling this feature can have an impact on your application. Make sure that you understand the impact before enabling it.<br><br>Refer for more details:<br>https://docs.microsoft.com/en-us/azure/cosmos-db/role-based-access-control#check-list-before-enabling",
    "Resource Type": "azurerm_cosmosdb_account",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cosmosdb_account"
}