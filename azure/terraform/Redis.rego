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

redis_dont_have_private_endpoint ["public_network_access_disabled"] {
    count([c | input.resources[_].type == "azurerm_private_link_service"; c := 1]) == 0
}

redis_dont_have_private_endpoint ["public_network_access_disabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    count([c | r := input.resources[_];
              r.type == "azurerm_private_link_service";
              contains(r.properties.nat_ip_configuration[_].subnet_id, resource.properties.subnet_id);
              c := 1]) == 0
}

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

public_network_access_disabled {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not redis_dont_have_private_endpoint["public_network_access_disabled"]
} 

public_network_access_disabled {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["public_network_access_disabled"]
    not azure_issue["public_network_access_disabled"]
}

public_network_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["public_network_access_disabled"]
    redis_dont_have_private_endpoint["public_network_access_disabled"]
}

public_network_access_disabled = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["public_network_access_disabled"]
    redis_dont_have_private_endpoint["public_network_access_disabled"]
}

public_network_access_disabled_err = "azurerm_redis_cache and azurerm_private_link_service or azurerm_redis_cache's property 'public_network_access_enabled' need to be exist. Its missing from the resource. Please set the value to false after property addition." {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["public_network_access_disabled"]
    redis_dont_have_private_endpoint["public_network_access_disabled"]
} else = "Redis cache currently does not have public network access disabled" {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["public_network_access_disabled"]
    redis_dont_have_private_endpoint["public_network_access_disabled"]
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
    count(resource.properties.subnet_id) == 0
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
    "Policy Description": "Azure Virtual Network deployment provides enhanced security and isolation for your Azure Cache for Redis, as well as subnets, access control policies, and other features to further restrict access. When an Azure Cache for Redis instance is configured with a virtual network, it is not publicly addressable and can only be accessed from virtual machines and applications within the virtual network.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}


# PR-AZR-TRF-ARC-005

default redis_cache_uses_privatelink = null

# azure_attribute_absence ["redis_cache_uses_privatelink"] {
#     count([c | input.resources[_].type == "azurerm_private_endpoint"; c := 1]) == 0
# }

azure_attribute_absence ["redis_cache_uses_privatelink"] {
    count([c | input.resources[_].type == "azurerm_private_link_service"; c := 1]) == 0
}

# azure_issue ["redis_cache_uses_privatelink"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_redis_cache"
#     count([c | r := input.resources[_];
#               r.type == "azurerm_private_endpoint";
#               contains(r.properties.private_service_connection[_].private_connection_resource_id, resource.properties.compiletime_identity);
#               c := 1]) == 0
#     count([c | r := input.resources[_];
#               r.type == "azurerm_private_endpoint";
#               contains(r.properties.private_service_connection[_].private_connection_resource_id, concat(".", [resource.type, resource.name]));
#               c := 1]) == 0
#     count([c | r := input.resources[_];
#               r.type == "azurerm_private_endpoint";
#               contains(r.properties.private_service_connection[_].private_connection_resource_alias, resource.properties.compiletime_identity);
#               c := 1]) == 0
#     count([c | r := input.resources[_];
#               r.type == "azurerm_private_endpoint";
#               contains(r.properties.private_service_connection[_].private_connection_resource_alias, concat(".", [resource.type, resource.name]));
#               c := 1]) == 0
# }

azure_issue ["redis_cache_uses_privatelink"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    count([c | r := input.resources[_];
              r.type == "azurerm_private_link_service";
              contains(r.properties.nat_ip_configuration[_].subnet_id, resource.properties.subnet_id);
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

redis_cache_uses_privatelink_err = "azurerm_redis_cache subnet should have ip configured with azurerm_private_link_service and this need to have a link with azurerm_private_endpoint and azurerm_private_endpoint's private_service_connection either need to have 'private_connection_resource_id' or 'private_connection_resource_alias' of azurerm_private_link_service. Seems there is no link established or mentioed properties are missing." {
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
    "Policy Description": "Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Cache for Redis instances via private link service, data leakage risks are reduced.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}


# https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache

# PR-AZR-TRF-ARC-006

default redis_persistence_enabled = null

azure_attribute_absence["redis_persistence_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    not resource.properties.redis_configuration
}

azure_attribute_absence["redis_persistence_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    redis_configuration := resource.properties.redis_configuration[_]
    not redis_configuration.rdb_backup_enabled
}

azure_issue["redis_persistence_enabled"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    redis_configuration := resource.properties.redis_configuration[_]
    redis_configuration.rdb_backup_enabled != true
}

redis_persistence_enabled {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["redis_persistence_enabled"]
    not azure_issue["redis_persistence_enabled"]
}

redis_persistence_enabled = false {
    azure_attribute_absence["redis_persistence_enabled"]
}

redis_persistence_enabled = false {
    azure_issue["redis_persistence_enabled"]
}

redis_persistence_enabled_err = "azurerm_redis_cache property 'redis_configuration.rdb_backup_enabled' need to be exist. Currently its missing from the resource. Please set the value to 'true' after property addition." {
    azure_attribute_absence["redis_persistence_enabled"]
} else = "Redis Cache Persistence is currently not enabled." {
    azure_issue["redis_persistence_enabled"]
}

redis_persistence_enabled_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-006",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Persistence is enabled on Redis Cache to Perform complete system backups",
    "Policy Description": "Enable Redis persistence. Redis persistence allows you to persist data stored in Redis. You can also take snapshots and back up the data, which you can load in case of a hardware failure. This is a huge advantage over Basic or Standard tier where all the data is stored in memory and there can be potential data loss in case of a failure where Cache nodes are down.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}


# PR-AZR-TRF-ARC-007

default redis_tls_has_latest_version = null
# default is 1.0
azure_attribute_absence ["redis_tls_has_latest_version"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    not resource.properties.minimum_tls_version
}

azure_issue ["redis_tls_has_latest_version"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    to_number(resource.properties.minimum_tls_version) != 1.2
}

redis_tls_has_latest_version {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["redis_tls_has_latest_version"]
    not azure_issue["redis_tls_has_latest_version"]
}

redis_tls_has_latest_version = false {
    azure_attribute_absence["redis_tls_has_latest_version"]
}

redis_tls_has_latest_version = false {
    azure_issue["redis_tls_has_latest_version"]
}

redis_tls_has_latest_version_err = "azurerm_redis_cache property 'minimum_tls_version' need to be exist. Currently its missing from the resource. Please set the value to '1.2' after property addition." {
    azure_attribute_absence["redis_persistence_enabled"]
} else = "Redis Cache currently does not have latest version of tls configured." {
    azure_issue["redis_persistence_enabled"]
}

redis_tls_has_latest_version_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-007",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Ensure Redis Cache has latest version of tls configured",
    "Policy Description": "This policy will identify the Redis Cache which doesn't have the latest version of tls configured and give alert.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}


#
# PR-AZR-TRF-ARC-008
#

default redis_cache_firewall_not_allowing_full_inbound_access = null


azure_attribute_absence ["redis_cache_firewall_not_allowing_full_inbound_access"] {
    count([c | input.resources[_].type == "azurerm_redis_firewall_rule"; c := 1]) == 0
}

azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_firewall_rule"
    not resource.properties.start_ip
}

azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_firewall_rule"
    not resource.properties.end_ip
}

azure_issue["redis_cache_firewall_not_allowing_full_inbound_access"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    count([c | r := input.resources[_];
              r.type == "azurerm_redis_firewall_rule";
              contains(r.properties.redis_cache_name, resource.properties.compiletime_identity);
              not contains(r.properties.start_ip, "0.0.0.0");
              not contains(r.properties.end_ip, "0.0.0.0");
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_redis_firewall_rule";
              contains(r.properties.redis_cache_name, concat(".", [resource.type, resource.name]));
              not contains(r.properties.start_ip, "0.0.0.0");
              not contains(r.properties.end_ip, "0.0.0.0");
              c := 1]) == 0
}

redis_cache_firewall_not_allowing_full_inbound_access {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"]
    not azure_issue["redis_cache_firewall_not_allowing_full_inbound_access"]
}

redis_cache_firewall_not_allowing_full_inbound_access = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"]
}

redis_cache_firewall_not_allowing_full_inbound_access = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["redis_cache_firewall_not_allowing_full_inbound_access"]
}

redis_cache_firewall_not_allowing_full_inbound_access_err = "azurerm_redis_firewall_rule resoruce or its property 'start_ip' or 'end_ip' is missing from the resource" {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["redis_cache_firewall_not_allowing_full_inbound_access"]
} else = "Redis Cache firewall rule configuration currently allowing full inbound access to everyone" {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["redis_cache_firewall_not_allowing_full_inbound_access"]
}

redis_cache_firewall_not_allowing_full_inbound_access_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-008",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Redis Cache Firewall rules should not configure to allow full inbound access to everyone",
    "Policy Description": "Firewalls grant access to redis cache based on the originating IP address of each request and should be within the range of START IP and END IP. Firewall settings with START IP and END IP both with 0.0.0.0 represents access to all Azure internal network. This setting needs to be turned-off to remove blanket access.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_firewall_rule"
}


# PR-AZR-TRF-ARC-009
default redis_cache_uses_private_dns_zone = null


azure_attribute_absence ["redis_cache_uses_private_dns_zone"] {
    count([c | input.resources[_].type == "azurerm_private_dns_zone_virtual_network_link"; c := 1]) == 0
}

azure_issue["redis_cache_uses_private_dns_zone"] {
    resource := input.resources[_]
    lower(resource.type) == "azurerm_redis_cache"
    count([c | r := input.resources[_];
              r.type == "azurerm_subnet";
              contains(resource.properties.subnet_id, r.properties.compiletime_identity);
              count([ci | ri := input.resources[_];
              ri.type == "azurerm_private_dns_zone_virtual_network_link";
              contains(ri.properties.virtual_network_id, r.properties.virtual_network_name);
              ci := 1]) > 0;
              c := 1]) == 0
    count([c | r := input.resources[_];
              r.type == "azurerm_subnet";
              contains(resource.properties.subnet_id, concat(".", [r.type, r.name]));
              count([ci | ri := input.resources[_];
              ri.type == "azurerm_private_dns_zone_virtual_network_link";
              contains(ri.properties.virtual_network_id, r.properties.virtual_network_name);
              ci := 1]) > 0;
              c := 1]) == 0
}

# azure_issue ["redis_cache_uses_privatelink"] {
#     resource := input.resources[_]
#     lower(resource.type) == "azurerm_redis_cache"
#     count([c | r := input.resources[_];
#               r.type == "azurerm_private_link_service";
#               contains(r.properties.nat_ip_configuration[_].subnet_id, resource.properties.subnet_id);
#               c := 1]) == 0
# }

redis_cache_uses_private_dns_zone = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["redis_cache_uses_private_dns_zone"]
}

redis_cache_uses_private_dns_zone {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    not azure_attribute_absence["redis_cache_uses_private_dns_zone"]
    not azure_issue["redis_cache_uses_private_dns_zone"]
}

redis_cache_uses_private_dns_zone = false {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["redis_cache_uses_private_dns_zone"]
}

redis_cache_uses_private_dns_zone_err = "azurerm_redis_cache vnet should have network link configured with private DNS zone via azurerm_private_dns_zone_virtual_network_link. Seems its not configured." {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_attribute_absence["redis_cache_uses_private_dns_zone"]
} else = "Redis cache currently not configured to use private DNS zone" {
    lower(input.resources[_].type) == "azurerm_redis_cache"
    azure_issue["redis_cache_uses_private_dns_zone"]
}

redis_cache_uses_private_dns_zone_metadata := {
    "Policy Code": "PR-AZR-TRF-ARC-009",
    "Type": "IaC",
    "Product": "AZR",
    "Language": "Terraform",
    "Policy Title": "Azure Cache for Redis should configure to use private DNS zone",
    "Policy Description": "Use private DNS zones to override the DNS resolution for a private endpoint. A private DNS zone can be linked to your virtual network to resolve to Azure Cache for Redis.",
    "Resource Type": "azurerm_redis_cache",
    "Policy Help URL": "",
    "Resource Help URL": "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/redis_cache"
}