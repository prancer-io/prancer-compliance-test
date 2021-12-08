package rule

has_property(parent_object, target_property) { 
	_ = parent_object[target_property]
}

# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache

# PR-AZR-TRF-ARC-001

default enableSslPort = null
# default is false
azure_attribute_absence ["enableSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    not resource.properties.enable_non_ssl_port
}

azure_issue ["enableSslPort"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    resource.properties.enable_non_ssl_port != false
}

enableSslPort {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["enableSslPort"]
    not azure_issue["enableSslPort"]
}

enableSslPort {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["enableSslPort"]
    not azure_issue["enableSslPort"]
}

enableSslPort = false {
    azure_issue["enableSslPort"]
}

enableSslPort_err = "Redis cache is currently allowing unsecure connection via a non ssl port opened" {
    azure_issue["enableSslPort"]
}

enableSslPort_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-001",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure that the Redis Cache accepts only SSL connections",
    "Policy Description": "It is recommended that Redis Cache should allow only SSL connections. Note: some Redis tools (like redis-cli) do not support SSL. When using such tools plain connection ports should be enabled.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}



# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_linked_server

# PR-AZR-TRF-ARC-002

default serverRole = null
# as azurerm_redis_linked_server is child resource of microsoft.cache/redis, we need to make sure microsoft.cache/redis exist in the same template first.
azure_attribute_absence["serverRole"] {
    count([c | input.resources[_].type == "azurerm_redis_linked_server"; c := 1]) == 0
}

azure_attribute_absence ["serverRole"] {
   resource := input.resources[_]
   lower(resource.type) == "azurerm_redis_linked_server"
   not resource.properties.server_role
}

azure_issue ["serverRole"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_linked_server"
    lower(resource.properties.server_role) != "secondary"
}

serverRole = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["serverRole"]
}

serverRole {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["serverRole"]
    not azure_issue["serverRole"]
}

serverRole = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["serverRole"]
}

serverRole_err = "Azure Redis Cache linked server property 'server_role' is missing from the resource" {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["serverRole"]
} else = "Azure Redis Cache linked backup server currently does not have secondary role." {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["serverRole"]
}

serverRole_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-002",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Redis cache should have a backup",
    "Policy Description": "Replicate Redis Cache server data to another Redis Cache server using geo replication. This feature is only available for Premium tier Redis Cache. From performance point of view, Microsoft recommends that both Redis Caches (Primary and the linked secondary) reside in the same region.",
    "Resource Type": "azurerm_redis_linked_server",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_linked_server"
}


# PR-AZR-TRF-ARC-003

default public_network_access_disabled = null
# default is true
azure_attribute_absence ["public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    not has_property(resource.properties, "public_network_access_enabled")
}

azure_issue ["public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    resource.properties.public_network_access_enabled == true
}

public_network_access_disabled = false {
    azure_attribute_absence["public_network_access_disabled"]
}

public_network_access_disabled {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["public_network_access_disabled"]
    not azure_issue["public_network_access_disabled"]
}

public_network_access_disabled = false {
    azure_issue["public_network_access_disabled"]
}

public_network_access_disabled_err = "azurerm_redis_cache property 'public_network_access_enabled' need to be exist. Its missing from the resource. Please set the value to false after property addition." {
    azure_attribute_absence["public_network_access_disabled"]
} else = "Redis cache currently does not have public network access disabled" {
    azure_issue["public_network_access_disabled"]
}

public_network_access_disabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-003",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Cache for Redis should disable public network access",
    "Policy Description": "Disabling public network access improves security by ensuring that the Azure Cache for Redis isn't exposed on the public internet. You can limit exposure of your Azure Cache for Redis by creating private endpoints instead.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}

# PR-AZR-TRF-ARC-004

default redis_cache_inside_vnet = null

azure_attribute_absence ["redis_cache_inside_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    # Only available when using the Premium SKU The ID of the Subnet within which the Redis Cache should be deployed. This Subnet must only contain Azure Cache for Redis instances without any other type of resources. Changing this forces a new resource to be created.
    not resource.properties.subnet_id
}

azure_issue ["redis_cache_inside_vnet"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    resource.properties.subnet_id == true
}

redis_cache_inside_vnet = false {
    azure_attribute_absence["redis_cache_inside_vnet"]
}

redis_cache_inside_vnet {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["redis_cache_inside_vnet"]
    not azure_issue["redis_cache_inside_vnet"]
}

redis_cache_inside_vnet = false {
    azure_issue["redis_cache_inside_vnet"]
}

redis_cache_inside_vnet_err = "azurerm_redis_cache property 'subnet_id' need to be exist. Its missing from the resource." {
    azure_attribute_absence["redis_cache_inside_vnet"]
} else = "Redis cache currently does not reside within a virtual network" {
    azure_issue["redis_cache_inside_vnet"]
}

redis_cache_inside_vnet_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-004",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Cache for Redis should reside within a virtual network",
    "Policy Description": "Azure Virtual Network deployment provides enhanced security and isolation for your Azure Cache for Redis, as well as subnets, access control policies, and other features to further restrict access.When an Azure Cache for Redis instance is configured with a virtual network, it is not publicly addressable and can only be accessed from virtual machines and applications within the virtual network.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}


# PR-AZR-TRF-ARC-005

default redis_cache_uses_privatelink = null

azure_attribute_absence ["redis_cache_uses_privatelink"] {
    count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
}

azure_attribute_absence ["redis_cache_uses_privatelink"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_private_endpoint"
    not resource.properties.private_service_connection
}

azure_attribute_absence ["redis_cache_uses_privatelink"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_private_endpoint"
    private_service_connection := resource.properties.private_service_connection[_]
    not private_service_connection.private_connection_resource_id
    not private_service_connection.private_connection_resource_alias
}

azure_issue ["redis_cache_uses_privatelink"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_private_endpoint"
    private_service_connection := resource.properties.private_service_connection[_]
    count([c | r := input.resources[_];
              r.type == "azurerm_redis_cache";
              contains(private_service_connection.private_connection_resource_id, r.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_redis_cache";
              contains(private_service_connection.private_connection_resource_id, concat(".", [r.type, r.name]));
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_redis_cache";
              contains(private_service_connection.private_connection_resource_alias, r.properties.compiletime_identity);
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_redis_cache";
              contains(private_service_connection.private_connection_resource_alias, concat(".", [r.type, r.name]));
              c := 1]) == 0
}

redis_cache_uses_privatelink = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["redis_cache_uses_privatelink"]
}

redis_cache_uses_privatelink {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["redis_cache_uses_privatelink"]
    not azure_issue["redis_cache_uses_privatelink"]
}

redis_cache_uses_privatelink = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["redis_cache_uses_privatelink"]
}

redis_cache_uses_privatelink_err = "azurerm_redis_cache should have link with azurerm_private_endpoint and azurerm_private_endpoint's private_service_connection either need to have 'private_connection_resource_id' or 'private_connection_resource_alias' property. Seems there is no link established or mentioed properties are missing." {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["redis_cache_uses_privatelink"]
} else = "Redis cache currently not using private link" {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["redis_cache_uses_privatelink"]
}

redis_cache_uses_privatelink_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-005",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Cache for Redis should use private link",
    "Policy Description": "Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Cache for Redis instances, data leakage risks are reduced.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}