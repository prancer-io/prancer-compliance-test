package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

array_contains(target_array, element) = true {
  lower(target_array[_]) == lower(element)
} else = false { true }

# https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template
#
# PR-AZR-ARM-ACD-001
#

default acd_ip_range_filter_configured = null

azure_attribute_absence["acd_ip_range_filter_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    not resource.properties.ipRules
}

azure_attribute_absence["acd_ip_range_filter_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    ipRules := resource.properties.ipRules[_]
    not ipRules.ipAddressOrRange
}

azure_issue["acd_ip_range_filter_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    ipRules := resource.properties.ipRules[_]
    count(ipRules.ipAddressOrRange) == 0
}

acd_ip_range_filter_configured {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
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
} else = "Azure Cosmos DB attribute ipRules.ipAddressOrRange missing from the resource" {
    azure_attribute_absence["acd_ip_range_filter_configured"]
}

acd_ip_range_filter_configured_metadata := {
    "Policy Code": "PR-AZR-ARM-ACD-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Cosmos DB IP range filter should be configured",
    "Policy Description": "This policy identifies Azure Cosmos DB with IP range filter not configured. Azure Cosmos DB should be restricted access from All Networks. It is recommended to add defined set of IP / IP range which can access Azure Cosmos DB from the Internet.",
    "Resource Type": "microsoft.documentdb/databaseaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts/privateendpointconnections?pivots=deployment-language-arm-template
# PR-AZR-CLD-ACD-002

default azure_cosmos_db_configured_with_private_endpoint = null

azure_attribute_absence["azure_cosmos_db_configured_with_private_endpoint"] {
    count([c | lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts/privateendpointconnections"; c := 1]) == 0
}

azure_attribute_absence["azure_cosmos_db_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts/privateendpointconnections"
    not resource.dependsOn
}

azure_attribute_absence["azure_cosmos_db_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState
}

azure_attribute_absence["azure_cosmos_db_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts/privateendpointconnections"
    not resource.properties.privateLinkServiceConnectionState.status
}

azure_issue["azure_cosmos_db_configured_with_private_endpoint"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.documentdb/databaseaccounts/privateendpointconnections";
              array_contains(r.dependsOn, concat("/", [resource.type, resource.name]));
              lower(r.properties.privateLinkServiceConnectionState.status) == "approved";
              c := 1]) == 0
}

azure_cosmos_db_configured_with_private_endpoint {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
    not azure_attribute_absence["azure_cosmos_db_configured_with_private_endpoint"]
    not azure_issue["azure_cosmos_db_configured_with_private_endpoint"]
}

azure_cosmos_db_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
    azure_attribute_absence["azure_cosmos_db_configured_with_private_endpoint"]
}

azure_cosmos_db_configured_with_private_endpoint = false {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
    azure_issue["azure_cosmos_db_configured_with_private_endpoint"]
}

azure_cosmos_db_configured_with_private_endpoint_err = "Azure Cosmos DB currently dont have private endpoints configured" {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
    azure_issue["azure_cosmos_db_configured_with_private_endpoint"]
} else = "microsoft.documentdb/databaseaccounts/privateendpointconnections resoruce property 'privateLinkServiceConnectionState.status' is missing from the resource" {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
    azure_attribute_absence["azure_cosmos_db_configured_with_private_endpoint"]
}

azure_cosmos_db_configured_with_private_endpoint_metadata := {
    "Policy Code": "PR-AZR-CLD-ACD-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Cosmos DB should have private endpoints configured",
    "Policy Description": "This policy identifies Cosmos DBs that are not configured with a private endpoint connection. Azure Cosmos DB private endpoints can be configured using Azure Private Link. Private Link allows users to access an Azure Cosmos account from within the virtual network or from any peered virtual network. When Private Link is combined with restricted NSG policies, it helps reduce the risk of data exfiltration. It is recommended to configure Private Endpoint Connection to Cosmos DB.",
    "Resource Type": "microsoft.documentdb/databaseaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template
#
# PR-AZR-ARM-ACD-003
#

default acd_vnet_configured = null

azure_attribute_absence["acd_vnet_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    not has_property(resource.properties, "isVirtualNetworkFilterEnabled")
}

azure_issue["acd_vnet_configured"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    resource.properties.isVirtualNetworkFilterEnabled != true
}

acd_vnet_configured {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
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
} else = "Azure Cosmos DB attribute isVirtualNetworkFilterEnabled is missing from the resource" {
    azure_attribute_absence["acd_vnet_configured"]
}

acd_ip_range_filter_configured_metadata := {
    "Policy Code": "PR-AZR-ARM-ACD-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Cosmos DB Virtual network should be configured",
    "Policy Description": "This policy identifies Azure Cosmos DBs that are not configured with a Virtual network. Azure Cosmos DB by default is accessible from any source if the request is accompanied by a valid authorization token. By configuring Virtual network only requests originating from those subnets will get a valid response. It is recommended to configure Virtual network to Cosmos DB.",
    "Resource Type": "microsoft.documentdb/databaseaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template
#
# PR-AZR-ARM-ACD-004
#

default acd_ip_range_filter_configured_to_block_public_inbound_access = null

azure_attribute_absence["acd_ip_range_filter_configured_to_block_public_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    not resource.properties.ipRules
}

azure_attribute_absence["acd_ip_range_filter_configured_to_block_public_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    ipRules := resource.properties.ipRules[_]
    not ipRules.ipAddressOrRange
}

azure_issue["acd_ip_range_filter_configured_to_block_public_inbound_access"] {
    count([c | r := input.resources[_];
              lower(r.type) == "microsoft.documentdb/databaseaccounts";
              ipRules := r.properties.ipRules[_];
              contains(ipRules.ipAddressOrRange, "0.0.0.0");
              c := 1]) > 0
}

acd_ip_range_filter_configured_to_block_public_inbound_access {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
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
} else = "Azure Cosmos DB attribute ipRules.ipAddressOrRange missing from the resource. Make sure it does not contains 0.0.0.0" {
    azure_attribute_absence["acd_ip_range_filter_configured_to_block_public_inbound_access"]
}

acd_ip_range_filter_configured_to_block_public_inbound_access_metadata := {
    "Policy Code": "PR-AZR-ARM-ACD-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Cosmos DB shoud not allow traffic from public Azure datacenters",
    "Policy Description": "This policy identifies Cosmos DBs that allow traffic from public Azure datacenters. If you enable this option, the IP address 0.0.0.0 is added to the list of allowed IP addresses. The list of IPs allowed by this option is wide, so it limits the effectiveness of a firewall policy. So it is recommended not to select the 'Accept connections from within public Azure datacenters' option for your Cosmos DB.",
    "Resource Type": "microsoft.documentdb/databaseaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template"
}


# https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template
#
# PR-AZR-ARM-ACD-005
#

default acd_disbaled_key_based_metadata_write_access = null

azure_attribute_absence["acd_disbaled_key_based_metadata_write_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    not has_property(resource.properties, "disableKeyBasedMetadataWriteAccess")
}

azure_issue["acd_disbaled_key_based_metadata_write_access"] {
    resource := input.resources[_]
    lower(resource.type) == "microsoft.documentdb/databaseaccounts"
    resource.properties.disableKeyBasedMetadataWriteAccess != true
}

acd_disbaled_key_based_metadata_write_access {
    lower(input.resources[_].type) == "microsoft.documentdb/databaseaccounts"
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
} else = "Azure Cosmos DB attribute disableKeyBasedMetadataWriteAccess is missing from the resource." {
    azure_attribute_absence["acd_disbaled_key_based_metadata_write_access"]
}

acd_disbaled_key_based_metadata_write_access_metadata := {
    "Policy Code": "PR-AZR-ARM-ACD-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "ARM template",
    "Policy Title": "Azure Cosmos DB key based authentication should be disabled",
    "Policy Description": "This policy identifies Cosmos DBs that are enabled with key-based authentication. Disabling key-based metadata write access on Azure Cosmos DB prevents any changes to resources from a client connecting using the account keys. It is recommended to disable this feature for organizations who want higher degrees of control and governance for production environments.<br><br>NOTE: Enabling this feature can have an impact on your application. Make sure that you understand the impact before enabling it.<br><br>Refer for more details:<br>https://docs.microsoft.com/en-us/azure/cosmos-db/role-based-access-control#check-list-before-enabling",
    "Resource Type": "microsoft.documentdb/databaseaccounts",
    "Policy Help URL": "",
    "Resource Help URL": "https://learn.microsoft.com/en-us/azure/templates/microsoft.documentdb/databaseaccounts?pivots=deployment-language-arm-template"
}